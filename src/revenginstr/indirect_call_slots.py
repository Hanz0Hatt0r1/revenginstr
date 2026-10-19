"""Project exact indirect-call target loads into pointer-slot candidates."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterator

FORMAT = "REVENGINSTR.IndirectCallPointerSlot/1"
CALL_EVIDENCE_FORMAT = "REVENGINSTR.GhidraIndirectCallEvidence/1"
PROVENANCE_FORMAT = "REVENGINSTR.PointerProvenance/1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ADDRESS_RE = re.compile(r"^(?:(?P<space>[A-Za-z_$][\w$]*):)?(?:0x)?(?P<offset>[0-9a-fA-F]+)$")
TARGET_DEF_RE = re.compile(
    r"^def:(?P<opcode>[A-Z_]+)@(?P<address>(?:(?:[A-Za-z_$][\w$]*):)?(?:0x)?[0-9a-fA-F]+):"
    r"(?P<time>[0-9]+):(?P<size>[0-9]+)$"
)
OUTPUT_RE = re.compile(
    r"^def:(?P<address>(?:(?:[A-Za-z_$][\w$]*):)?(?:0x)?[0-9a-fA-F]+):"
    r"(?P<time>[0-9]+):(?P<size>[0-9]+)$"
)
DEFAULT_MAX_ROWS = 1_000_000


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-JSON numeric constant {value}")


def _read_jsonl(path: Path, *, max_rows: int) -> Iterator[tuple[int, dict[str, Any]]]:
    rows_seen = 0
    with path.open("r", encoding="utf-8", newline="") as handle:
        for line_no, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            rows_seen += 1
            if rows_seen > max_rows:
                raise ValueError(f"{path}: input row budget exceeded: {max_rows}")
            try:
                row = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
            except ValueError as error:
                raise ValueError(f"{path}:{line_no}: invalid JSON: {error}") from error
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_no}: expected a JSON object")
            yield line_no, row


def _address_key(value: Any, where: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{where}: expected address string")
    match = ADDRESS_RE.fullmatch(value.strip())
    if match is None:
        raise ValueError(f"{where}: unsupported address {value!r}")
    space = match.group("space")
    return f"{space.lower() + ':' if space else ''}0x{int(match.group('offset'), 16):x}"


def _positive_int(value: Any, where: str, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ValueError(f"{where}: expected integer >= {minimum}")
    return value


def _source_ref(path: Path, digest: str, record_index: int, source_format: str) -> dict[str, Any]:
    return {
        "source_format": source_format,
        "artifact_path": str(path),
        "artifact_sha256": digest,
        "record_index": record_index,
    }


def _validate_source(value: Any, where: str, *, nullable: bool = False) -> dict[str, Any] | None:
    if nullable and value is None:
        return None
    if not isinstance(value, dict) or set(value) != {
        "source_format", "artifact_path", "artifact_sha256", "record_index",
    }:
        raise ValueError(f"{where}: invalid evidence reference")
    if not isinstance(value["source_format"], str) or not value["source_format"]:
        raise ValueError(f"{where}: invalid source_format")
    if not isinstance(value["artifact_path"], str) or not value["artifact_path"]:
        raise ValueError(f"{where}: invalid artifact_path")
    if not isinstance(value["artifact_sha256"], str) or not SHA256_RE.fullmatch(value["artifact_sha256"]):
        raise ValueError(f"{where}: invalid artifact_sha256")
    _positive_int(value["record_index"], f"{where}: record_index")
    return value


def _read_callind_evidence(
    paths: list[Path], *, max_rows: int,
) -> dict[tuple[str, str, int], tuple[dict[str, Any], dict[str, Any]]]:
    if not paths:
        raise ValueError("at least one indirect-call evidence JSONL is required")
    rows: dict[tuple[str, str, int], tuple[dict[str, Any], dict[str, Any]]] = {}
    total_rows = 0
    for path in paths:
        digest = _sha256(path)
        for line_no, row in _read_jsonl(path, max_rows=max_rows):
            total_rows += 1
            if total_rows > max_rows:
                raise ValueError(f"combined indirect-call evidence row budget exceeded: {max_rows}")
            where = f"{path}:{line_no}"
            if set(row) != {
                "format", "program", "requested", "function_entry", "call_address",
                "call_time", "target", "target_expression", "arg_count",
            } or row.get("format") != CALL_EVIDENCE_FORMAT:
                raise ValueError(f"{where}: expected exact {CALL_EVIDENCE_FORMAT} fields")
            if not isinstance(row["program"], str) or not row["program"]:
                raise ValueError(f"{where}: program must be non-empty")
            if not isinstance(row["requested"], str) or not row["requested"]:
                raise ValueError(f"{where}: requested must be non-empty")
            if not isinstance(row["target"], str) or not row["target"]:
                raise ValueError(f"{where}: target must be non-empty")
            if not isinstance(row["target_expression"], str):
                raise ValueError(f"{where}: target_expression must be a string")
            call_time = _positive_int(row["call_time"], f"{where}: call_time", allow_zero=True)
            _positive_int(row["arg_count"], f"{where}: arg_count", allow_zero=True)
            key = (
                _address_key(row["function_entry"], f"{where}: function_entry"),
                _address_key(row["call_address"], f"{where}: call_address"),
                call_time,
            )
            if key in rows:
                raise ValueError(f"{where}: duplicate indirect-call site {key!r}")
            rows[key] = (row, _source_ref(path, digest, line_no, CALL_EVIDENCE_FORMAT))
    return rows


def _read_pointer_provenance(
    paths: list[Path], *, program_id: str, max_rows: int,
) -> tuple[
    dict[tuple[str, str, int], tuple[dict[str, Any], dict[str, Any]]],
    dict[tuple[str, str, int, int], tuple[dict[str, Any], dict[str, Any]]],
]:
    if not paths:
        raise ValueError("at least one PointerProvenance/1 JSONL is required")
    targets: dict[tuple[str, str, int], tuple[dict[str, Any], dict[str, Any]]] = {}
    outputs: dict[tuple[str, str, int, int], tuple[dict[str, Any], dict[str, Any]]] = {}
    total_rows = 0
    for path in paths:
        digest = _sha256(path)
        for line_no, row in _read_jsonl(path, max_rows=max_rows):
            total_rows += 1
            if total_rows > max_rows:
                raise ValueError(f"combined pointer-provenance row budget exceeded: {max_rows}")
            where = f"{path}:{line_no}"
            if set(row) != {
                "format", "record_kind", "evidence_class", "program_id", "function_entry",
                "operation_address", "operation_time", "opcode", "output_token", "status",
                "alternatives", "load_address", "source", "target_source",
            } or row.get("format") != PROVENANCE_FORMAT or row.get("evidence_class") != "derived_structural":
                raise ValueError(f"{where}: expected {PROVENANCE_FORMAT}")
            if row.get("program_id") != program_id:
                raise ValueError(f"{where}: program_id does not match {program_id!r}")
            kind = row.get("record_kind")
            if not isinstance(row.get("opcode"), str) or not row["opcode"]:
                raise ValueError(f"{where}: opcode must be a non-empty string")
            if not isinstance(row.get("output_token"), str) or not row["output_token"]:
                raise ValueError(f"{where}: output_token must be a non-empty string")
            if not isinstance(row.get("status"), str) or not row["status"]:
                raise ValueError(f"{where}: status must be a non-empty string")
            if not isinstance(row.get("alternatives"), list):
                raise ValueError(f"{where}: alternatives must be an array")
            if row.get("load_address") is not None and not isinstance(row["load_address"], dict):
                raise ValueError(f"{where}: load_address must be an object or null")
            function_key = _address_key(row.get("function_entry"), f"{where}: function_entry")
            address_key = _address_key(row.get("operation_address"), f"{where}: operation_address")
            time = _positive_int(row.get("operation_time"), f"{where}: operation_time", allow_zero=True)
            if kind == "callind_target":
                if row.get("opcode") != "CALLIND":
                    raise ValueError(f"{where}: invalid callind_target provenance row")
                _validate_source(row.get("source"), f"{where}: source")
                _validate_source(row.get("target_source"), f"{where}: target_source")
                key = (function_key, address_key, time)
                if key in targets:
                    raise ValueError(f"{where}: duplicate CALLIND provenance row {key!r}")
                targets[key] = (row, _source_ref(path, digest, line_no, PROVENANCE_FORMAT))
            elif kind == "operation_output":
                token = row.get("output_token")
                match = OUTPUT_RE.fullmatch(token) if isinstance(token, str) else None
                if match is None:
                    raise ValueError(f"{where}: invalid operation output token")
                token_key = (
                    function_key,
                    _address_key(match.group("address"), f"{where}: output token address"),
                    int(match.group("time")),
                    int(match.group("size")),
                )
                if token_key[:3] != (function_key, address_key, time):
                    raise ValueError(f"{where}: output token disagrees with operation identity")
                if token_key in outputs:
                    raise ValueError(f"{where}: duplicate operation output provenance {token_key!r}")
                _validate_source(row.get("source"), f"{where}: source")
                _validate_source(row.get("target_source"), f"{where}: target_source", nullable=True)
                outputs[token_key] = (row, _source_ref(path, digest, line_no, PROVENANCE_FORMAT))
            else:
                raise ValueError(f"{where}: unsupported record_kind {kind!r}")
    return targets, outputs


def build_indirect_call_pointer_slots(
    pointer_provenance_paths: list[Path],
    callind_evidence_paths: list[Path],
    *,
    program_id: str,
    max_rows: int = DEFAULT_MAX_ROWS,
) -> list[dict[str, Any]]:
    """Join indirect-call targets to their exact load-address provenance."""
    if not program_id:
        raise ValueError("program_id must be non-empty")
    if max_rows < 1:
        raise ValueError("max_rows must be positive")
    call_sites = _read_callind_evidence(callind_evidence_paths, max_rows=max_rows)
    target_rows, output_rows = _read_pointer_provenance(
        pointer_provenance_paths, program_id=program_id, max_rows=max_rows,
    )
    results: list[dict[str, Any]] = []
    for key, (call, call_source) in sorted(call_sites.items()):
        function_key, _, call_time = key
        target_match = TARGET_DEF_RE.fullmatch(call["target"])
        pointer_row_pair = target_rows.get(key)
        pointer_row = pointer_ref = None
        target_load_pair = None
        status = "missing_target_provenance"
        slot_access = None
        if pointer_row_pair is not None:
            pointer_row, pointer_ref = pointer_row_pair
            output_match = OUTPUT_RE.fullmatch(pointer_row["output_token"])
            if target_match is not None:
                target_identity = (
                    _address_key(target_match.group("address"), "indirect-call target address"),
                    int(target_match.group("time")),
                    int(target_match.group("size")),
                )
                pointer_identity = None if output_match is None else (
                    _address_key(output_match.group("address"), "provenance target address"),
                    int(output_match.group("time")),
                    int(output_match.group("size")),
                )
                if pointer_identity != target_identity:
                    raise ValueError(
                        f"{pointer_ref['artifact_path']}:{pointer_ref['record_index']}: "
                        "CALLIND target disagrees with exact indirect-call evidence"
                    )
            elif pointer_row["output_token"] != call["target"]:
                raise ValueError("CALLIND value target disagrees with exact indirect-call evidence")
            source = pointer_row.get("target_source")
            if source is None or (
                source.get("artifact_sha256"), source.get("record_index"), source.get("source_format")
            ) != (
                call_source["artifact_sha256"], call_source["record_index"], CALL_EVIDENCE_FORMAT
            ):
                raise ValueError("CALLIND provenance row is not linked to the supplied exact target evidence")

            if target_match is None:
                status = "non_load_target"
            else:
                output_key = (
                    function_key,
                    _address_key(target_match.group("address"), "target load address"),
                    int(target_match.group("time")),
                    int(target_match.group("size")),
                )
                target_load_pair = output_rows.get(output_key)
                if target_load_pair is None:
                    status = "missing_target_definition"
                else:
                    target_load = target_load_pair[0]
                    if target_load.get("opcode") != target_match.group("opcode"):
                        raise ValueError("target token opcode disagrees with exact P-code provenance")
                    if target_match.group("opcode") != "LOAD":
                        status = "unsupported_target_operation"
                    else:
                        load_address = target_load.get("load_address")
                        if not isinstance(load_address, dict):
                            status = "missing_load_address"
                        else:
                            alternatives = load_address.get("alternatives")
                            if not isinstance(alternatives, list) or any(
                                not isinstance(item, dict) for item in alternatives
                            ):
                                raise ValueError("target load provenance has malformed address alternatives")
                            if len(alternatives) != 1:
                                status = "ambiguous_address"
                            else:
                                alternative = alternatives[0]
                                root_kind = alternative.get("root_kind")
                                root_id = alternative.get("root_id")
                                offset = alternative.get("offset_bytes")
                                pointer_size = alternative.get("pointer_size_bytes")
                                output_size = int(target_match.group("size"))
                                if load_address.get("status") != "resolved" or alternative.get("status") != "resolved":
                                    status = "unresolved_address"
                                elif root_kind not in {"memory_read_anchor", "address_anchor"} or not isinstance(root_id, str) or not root_id:
                                    status = "unsupported_address_root"
                                elif isinstance(offset, bool) or not isinstance(offset, int) or isinstance(pointer_size, bool) or not isinstance(pointer_size, int) or pointer_size < 1:
                                    status = "unresolved_address"
                                elif pointer_size != output_size:
                                    status = "width_mismatch"
                                elif offset % pointer_size:
                                    status = "unaligned_slot_offset"
                                else:
                                    status = "slot_access_candidate"
                                    slot_access = {
                                        "base_root_kind": root_kind,
                                        "base_root_id": root_id,
                                        "offset_bytes": offset,
                                        "pointer_size_bytes": pointer_size,
                                    }

        results.append({
            "format": FORMAT,
            "program_id": program_id,
            "binary_program": call["program"],
            "function_entry": call["function_entry"],
            "call_address": call["call_address"],
            "call_time": call_time,
            "target_token": call["target"],
            "target_expression": call["target_expression"],
            "status": status,
            "slot_access": slot_access,
            "source": {
                "indirect_call_evidence": call_source,
                "callind_target_provenance": pointer_ref,
                "target_definition_provenance": target_load_pair[1] if target_load_pair else None,
            },
        })
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--program-id", required=True, help="opaque identity shared by PointerProvenance inputs")
    parser.add_argument("--pointer-provenance", type=Path, action="append", required=True)
    parser.add_argument("--indirect-call-evidence", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-rows", type=int, default=DEFAULT_MAX_ROWS)
    args = parser.parse_args(argv)
    rows = build_indirect_call_pointer_slots(
        args.pointer_provenance, args.indirect_call_evidence,
        program_id=args.program_id, max_rows=args.max_rows,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    print("output rows:", len(rows))
    print("statuses:", dict(sorted(Counter(row["status"] for row in rows).items())))
    print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
