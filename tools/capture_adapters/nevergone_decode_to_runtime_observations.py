#!/usr/bin/env python3
"""Normalize the bounded Decode events emitted by Nevergone Trace Kit v2."""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROGRAM_SHA = "94b1ef6a9469e261183ac08199c5b0eb65c0c40b81918ca097bd32920828eb5e"
PROGRAM_ID = "nevergone-1.0.9-armv7-libcocos2dcpp"
DECODE_SYMBOL = "_ZN7cocos2d6DecodeEPhiS0_j"
FILE_DATA_SYMBOL = "_ZN7cocos2d18CCFileUtilsAndroid11getFileDataEPKcS2_Pm"
MAX_TRACE_BYTES = 64 * 1024 * 1024
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _jsonl(path: Path) -> tuple[list[dict[str, Any]], bytes]:
    raw = path.read_bytes()
    if len(raw) > MAX_TRACE_BYTES:
        raise ValueError("trace exceeds 64 MiB")
    try:
        rows = [json.loads(line, object_pairs_hook=_unique_object) for line in raw.decode("utf-8").splitlines() if line.strip()]
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"invalid trace JSONL: {error}") from error
    if any(not isinstance(row, dict) for row in rows):
        raise ValueError("trace rows must be JSON objects")
    return rows, raw


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _number(value: Any, where: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ValueError(f"{where}: expected integer in [0, {maximum}]")
    return value


def _hex(value: Any, where: str) -> int:
    if not isinstance(value, str):
        raise ValueError(f"{where}: expected hexadecimal string")
    text = value[2:] if value.startswith("0x") else value
    if not text or not re.fullmatch(r"[0-9a-fA-F]{1,16}", text):
        raise ValueError(f"{where}: invalid hexadecimal string")
    return int(text, 16)


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("--probe-script", type=Path, required=True)
    parser.add_argument("--semantic-graph", type=Path, required=True)
    parser.add_argument("--capture-id", required=True)
    parser.add_argument("--static-entry", default="0x544a40")
    parser.add_argument("--static-image-base", default="0x10000")
    parser.add_argument("--installed-apk-sha256", required=True)
    parser.add_argument("--value-token-key-file", type=Path)
    parser.add_argument("--application-version", default="1.0.9")
    parser.add_argument("--device-model", default="Redmi Note 8 Pro")
    parser.add_argument("--device-code", default="begonia")
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if not _SHA256.fullmatch(args.installed_apk_sha256):
        raise ValueError("installed APK hash must be lowercase SHA-256")
    if not args.capture_id.strip():
        raise ValueError("capture_id must not be empty")
    token_key = args.value_token_key_file.read_bytes() if args.value_token_key_file else None
    if token_key is not None and not 32 <= len(token_key) <= 4096:
        raise ValueError("value token key must contain 32 to 4096 bytes")

    trace_rows, trace_raw = _jsonl(args.trace)
    try:
        graph = json.loads(args.semantic_graph.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"invalid semantic graph: {error}") from error
    if not isinstance(graph, dict) or graph.get("program_id") != PROGRAM_ID:
        raise ValueError("semantic graph does not identify the pinned Nevergone program")
    target_nodes = [
        node for node in graph.get("nodes", [])
        if node.get("kind") == "function" and _hex(node.get("entry"), "graph function entry") == _hex(args.static_entry, "static-entry")
    ]
    if len(target_nodes) != 1:
        raise ValueError("semantic graph has no function at static-entry")

    headers = [row for row in trace_rows if row.get("type") == "header"]
    modules = [row for row in trace_rows if row.get("type") == "module" and row.get("name") == "libcocos2dcpp.so"]
    indexed_events = [
        (index, row) for index, row in enumerate(trace_rows)
        if row.get("type") == "call" and row.get("symbol") == DECODE_SYMBOL
    ]
    events = [row for _, row in indexed_events]
    file_data_events = [
        (index, row) for index, row in enumerate(trace_rows)
        if row.get("type") == "call" and row.get("symbol") == FILE_DATA_SYMBOL
    ]
    if len(headers) != 1 or len(modules) != 1 or not events:
        raise ValueError("trace must contain one header, one libcocos2dcpp module, and Decode calls")
    if headers[0].get("package") != "com.hippiegame.nevergone" or headers[0].get("arch") != "arm":
        raise ValueError("trace package or architecture does not match Nevergone ARM32")
    module_base = _hex(modules[0].get("base"), "module base")
    static_entry = _hex(args.static_entry, "static-entry")
    image_base = _hex(args.static_image_base, "static-image-base")
    if static_entry < image_base:
        raise ValueError("static-entry precedes static-image-base")
    expected_elf_vma = static_entry - image_base
    script_sha = _digest(args.probe_script)
    trace_sha = hashlib.sha256(trace_raw).hexdigest()
    graph_sha = _digest(args.semantic_graph)

    addresses: list[dict[str, Any]] = []
    transforms: list[dict[str, Any]] = []
    direct_calls: list[dict[str, Any]] = []
    value_flow_addresses: list[dict[str, Any]] = []
    value_observations: list[dict[str, Any]] = []
    value_candidates: list[dict[str, Any]] = []
    ordinals: set[int] = set()
    callsite_facts: dict[int, dict[str, Any]] = {}
    for sequence, (row_index, event) in enumerate(indexed_events):
        offset = _hex(event.get("offset"), f"Decode event {sequence + 1} offset")
        if offset & ~1 != expected_elf_vma:
            raise ValueError(f"Decode event {sequence + 1} does not map to the requested static function")
        return_offset = _hex(event.get("callsite"), f"Decode event {sequence + 1} callsite")
        if return_offset & 1 == 0:
            raise ValueError(f"Decode event {sequence + 1} return address is not Thumb-tagged")
        callsite_elf_vma = (return_offset & ~1) - 4
        if callsite_elf_vma < 0:
            raise ValueError(f"Decode event {sequence + 1} return address precedes a Thumb BL")
        callsite_static_address = callsite_elf_vma + image_base
        callsite_nodes = [
            node for node in graph.get("nodes", [])
            if node.get("kind") == "operation" and node.get("opcode") == "CALL"
            and _hex(node.get("operation_address"), "graph direct call address") == callsite_static_address
        ]
        if len(callsite_nodes) != 1 or callsite_nodes[0].get("target_entries") != [f"{static_entry:08x}"]:
            raise ValueError(f"Decode event {sequence + 1} return address does not identify one direct CALL to the selected function")
        typed = event.get("typed")
        if not isinstance(typed, dict) or typed.get("kind") != "decode":
            raise ValueError(f"Decode event {sequence + 1} has no typed observation")
        ordinal = _number(event.get("ordinal"), "source ordinal", 1_000_000_000)
        if ordinal == 0 or ordinal in ordinals:
            raise ValueError("trace has duplicate or invalid Decode ordinals")
        ordinals.add(ordinal)
        length = _number(typed.get("input_length"), "input length", 0xFFFFFFFF)
        key = _number(typed.get("key"), "key", 0xFFFFFFFF)
        sample_count = _number(typed.get("sample_count"), "sample count", 128)
        script_mode = typed.get("sample_mode")
        mode = {"empty": "none", "full": "full", "evenly_spaced": "bounded"}.get(script_mode)
        if mode is None:
            mode = "none"
        result = (
            "match" if typed.get("formula_matches") is True
            else "mismatch" if typed.get("formula_matches") is False
            else "unavailable"
        )
        if mode == "none" and (sample_count != 0 or result != "unavailable"):
            raise ValueError(f"Decode event {sequence + 1} has inconsistent empty-sample fields")
        address = module_base + expected_elf_vma
        runtime_callsite_address = module_base + callsite_elf_vma
        callsite_facts[callsite_elf_vma] = {
            "static_address": f"0x{callsite_static_address:x}",
            "node_id": callsite_nodes[0]["id"],
            "caller_entry": callsite_nodes[0]["function_entry"],
        }
        addresses.append({
            "format": "REVENGINSTR.RuntimeAddressObservation/1",
            "capture_id": args.capture_id,
            "sequence": sequence,
            "event_kind": "function_entry",
            "runtime_address": f"0x{address:x}",
        })
        transforms.append({
            "format": "REVENGINSTR.RuntimeTransformObservation/1",
            "capture_id": args.capture_id,
            "correlation_sequence": sequence,
            "runtime_address": f"0x{address:x}",
            "event_kind": "function_entry",
            "behavior_id": "nevergone-decode-xor-subtract-index-mod-127-u8/v1",
            "source_ordinal": ordinal,
            "input_length": length,
            "key": key,
            "sample_mode": mode,
            "sample_count": sample_count,
            "formula_result": result,
            "probe_script_sha256": script_sha,
        })
        direct_calls.append({
            "format": "REVENGINSTR.RuntimeDirectCallObservation/1",
            "capture_id": args.capture_id,
            "sequence": sequence,
            "callsite_runtime_address": f"0x{runtime_callsite_address:x}",
            "target_runtime_address": f"0x{address:x}",
        })
        if token_key is not None:
            thread_id = event.get("tid")
            if isinstance(thread_id, bool) or not isinstance(thread_id, int) or thread_id < 0:
                raise ValueError("Decode event has no valid thread id for return pairing")
            caller_entry = _hex(callsite_nodes[0].get("function_entry"), "direct CALL owner entry")
            caller_nodes = [
                node for node in graph.get("nodes", [])
                if node.get("kind") == "function"
                and _hex(node.get("entry"), "graph function entry") == caller_entry
            ]
            caller_elf_vma = caller_entry - image_base
            if len(caller_nodes) != 1 or caller_elf_vma < 0:
                raise ValueError("direct CALL owner does not identify one in-range function")
            parent_match = next((
                (candidate_index, candidate) for candidate_index, candidate in file_data_events
                if candidate_index > row_index and candidate.get("tid") == thread_id
            ), None)
            if parent_match is None or not isinstance(parent_match[1].get("typed"), dict):
                raise ValueError("Decode call has no later same-thread getFileData return")
            parent_index, parent = parent_match
            if any(
                row_index < index < parent_index and candidate.get("symbol") == DECODE_SYMBOL
                and candidate.get("tid") == thread_id
                for index, candidate in indexed_events
            ):
                raise ValueError("nested Decode calls make the enclosing getFileData return ambiguous")
            parent_typed = parent["typed"]
            if (
                parent_typed.get("kind") != "get_file_data"
                or _hex(parent.get("offset"), "getFileData entry") & ~1 != caller_elf_vma
                or parent_typed.get("success") is not True
            ):
                raise ValueError("next same-thread return is not a successful direct-call owner")
            destination = _hex(typed.get("destination_ptr"), "Decode destination pointer")
            returned = _hex(parent_typed.get("returned_data_pointer"), "getFileData return pointer")
            if destination == 0 or destination != returned:
                raise ValueError("Decode destination and enclosing getFileData return do not match")
            pair_sequence = sequence * 2
            pointer_token = "hmac-sha256:" + hmac.new(
                token_key,
                f"{args.capture_id}\0runtime-pointer\0{destination:x}".encode("ascii"),
                hashlib.sha256,
            ).hexdigest()
            caller_address = module_base + caller_elf_vma
            value_flow_addresses.extend((
                {
                    "format": "REVENGINSTR.RuntimeAddressObservation/1",
                    "capture_id": args.capture_id,
                    "sequence": pair_sequence,
                    "event_kind": "call_target",
                    "runtime_address": f"0x{address:x}",
                },
                {
                    "format": "REVENGINSTR.RuntimeAddressObservation/1",
                    "capture_id": args.capture_id,
                    "sequence": pair_sequence + 1,
                    "event_kind": "function_exit",
                    "runtime_address": f"0x{caller_address:x}",
                },
            ))
            value_observations.extend((
                {
                    "format": "REVENGINSTR.RuntimeValueObservation/1",
                    "capture_id": args.capture_id,
                    "correlation_sequence": pair_sequence,
                    "event_kind": "call_output",
                    "runtime_address": f"0x{address:x}",
                    "tokens": {"subject": pointer_token},
                },
                {
                    "format": "REVENGINSTR.RuntimeValueObservation/1",
                    "capture_id": args.capture_id,
                    "correlation_sequence": pair_sequence + 1,
                    "event_kind": "function_return",
                    "runtime_address": f"0x{caller_address:x}",
                    "tokens": {"subject": pointer_token},
                },
            ))
            value_candidates.append({
                "candidate_id": f"decode-output-return-{sequence + 1:03d}",
                "relation_kind": "call_output_return",
                "source_sequence": pair_sequence,
                "sink_sequence": pair_sequence + 1,
                "expected_source_node_id": target_nodes[0]["id"],
                "expected_sink_node_id": caller_nodes[0]["id"],
            })

    identity = {
        "format": "REVENGINSTR.RuntimeStaticIdentity/1",
        "program_id": PROGRAM_ID,
        "program_sha256": PROGRAM_SHA,
        "semantic_graph_sha256": graph_sha,
        "static_image_base": f"0x{image_base:x}",
    }
    identity_raw = (json.dumps(identity, indent=2, sort_keys=True) + "\n").encode()
    capture = {
        "format": "REVENGINSTR.RuntimeCaptureManifest/1",
        "capture_id": args.capture_id,
        "program_id": PROGRAM_ID,
        "program_sha256": PROGRAM_SHA,
        "static_identity_sha256": hashlib.sha256(identity_raw).hexdigest(),
        "runtime_module_base": f"0x{module_base:x}",
        "sampling_status": "unknown",
        "sampling_gaps": [],
    }
    matched = sum(row["formula_result"] == "match" for row in transforms)
    mismatched = sum(row["formula_result"] == "mismatch" for row in transforms)
    unavailable = sum(row["formula_result"] == "unavailable" for row in transforms)
    metadata = {
        "format": "REVENGINSTR.NevergoneDecodeCaptureMetadata/1",
        "capture_id": args.capture_id,
        "captured_at_utc": datetime.fromtimestamp(headers[0]["ts_ms"] / 1000, timezone.utc).isoformat(),
        "package": headers[0]["package"],
        "application_version": args.application_version,
        "device_model": args.device_model,
        "device_code": args.device_code,
        "android_abi": "armeabi-v7a",
        "program_sha256": PROGRAM_SHA,
        "installed_apk_sha256": args.installed_apk_sha256,
        "probe_script_sha256": script_sha,
        "source_trace_sha256": trace_sha,
        "adapter_sha256": _digest(Path(__file__).resolve()),
        "runtime_module_base": capture["runtime_module_base"],
        "static_function_entry": f"0x{static_entry:x}",
        "elf_vma": f"0x{expected_elf_vma:x}",
        "hook_symbol_offset": events[0]["offset"],
        "function_node_id": target_nodes[0]["id"],
        "direct_call_observations": len(direct_calls),
        "callsite_return_offsets": sorted({event["callsite"] for event in events}),
        "callsite_elf_vmas": [f"0x{vma:x}" for vma in sorted(callsite_facts)],
        "callsite_facts": [callsite_facts[vma] for vma in sorted(callsite_facts)],
        "decode_call_rows": len(transforms),
        "nonempty_decode_calls": sum(row["input_length"] > 0 for row in transforms),
        "sampled_bytes": sum(row["sample_count"] for row in transforms),
        "formula_matches": matched,
        "formula_mismatches": mismatched,
        "unavailable_results": unavailable,
        "sampling_status": "unknown",
        "buffer_bytes_retained": False,
        **({
            "runtime_value_flow_pairs": len(value_candidates),
            "runtime_value_pointer_identity_matches": len(value_candidates),
            "runtime_value_token_scheme": "capture-scoped HMAC-SHA-256",
        } if token_key is not None else {}),
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    _write_json(args.output_dir / "static-identity.json", identity)
    _write_json(args.output_dir / "capture-manifest.json", capture)
    _write_json(args.output_dir / "capture-metadata.json", metadata)
    _write_jsonl(args.output_dir / "runtime-address-observations.jsonl", addresses)
    _write_jsonl(args.output_dir / "runtime-transform-observations.jsonl", transforms)
    _write_jsonl(args.output_dir / "runtime-direct-call-observations.jsonl", direct_calls)
    if token_key is not None:
        _write_jsonl(args.output_dir / "runtime-value-flow-address-observations.jsonl", value_flow_addresses)
        _write_jsonl(args.output_dir / "runtime-value-observations.jsonl", value_observations)
        _write_json(args.output_dir / "runtime-value-flow-candidates.json", value_candidates)
    print("Decode calls:", len(transforms))
    print("formula matches:", matched)
    print("formula mismatches:", mismatched)
    print("unavailable:", unavailable)
    print("direct CALL observations:", len(direct_calls))
    if token_key is not None:
        print("runtime value-flow pointer identity pairs:", len(value_candidates))
    print("output:", args.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
