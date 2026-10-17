"""Build provenance-linked structural feature sets for object-role clustering."""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from revenginstr.family.features import count_bucket
from revenginstr.object_roles import FEATURE_FORMAT
from revenginstr.structured_summary import validate_function_effect_ir

MANIFEST_FORMAT = "REVENGINSTR.ObjectRoleFeatureExtractionManifest/1"
EFFECT_FORMAT = "REVENGINSTR.FunctionEffectIR/1"
RECEIVER_FORMAT = "REVENGINSTR.ReceiverInference/1"
CALLGRAPH_FORMAT = "REVENGINSTR.CallGraphMetrics/1"
VTABLE_FORMAT = "REVENGINSTR.GhidraArm32ItaniumVtableSlots/1"
RECEIVER_STATUSES = {
    "receiver_not_single_pointer", "unresolved_receiver_class", "ambiguous_receiver_class",
    "ambiguous_class_vtable", "resolved_unique_vtable",
}
VTABLE_HEADER = (
    "vtable_symbol_start", "vtable_symbol_name", "address_point", "slot_offset",
    "slot_address", "raw_value", "target_thumb", "target_entry", "target_name",
    "target_signature", "resolution_mode", "next_vtable_symbol_start",
)
VTABLE_RESOLUTION_MODES = {
    "direct_ghidra_address", "image_base_plus_module_offset", "unexpected",
}
_OFFSET = re.compile(r"0x[0-9a-f]+\Z")


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _read_jsonl(path: Path) -> tuple[str, list[dict[str, Any]]]:
    raw = path.read_bytes()
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ValueError(f"{path}: input must be UTF-8") from error
    rows = []
    for line_no, line in enumerate(lines, 1):
        if not line.strip():
            raise ValueError(f"{path}:{line_no}: blank JSONL record")
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"{path}:{line_no}: invalid JSON") from error
        if not isinstance(row, dict):
            raise ValueError(f"{path}:{line_no}: expected an object")
        rows.append(row)
    return _sha256(raw), rows


def _read_vtable_tsv(path: Path) -> tuple[str, list[dict[str, str]]]:
    opener = gzip.open if path.suffix == ".gz" else Path.open
    with opener(path, "rt", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle, delimiter="\t", strict=True)
        if tuple(reader.fieldnames or ()) != VTABLE_HEADER:
            raise ValueError(f"{path}: unexpected vtable TSV header")
        rows = []
        for row_index, row in enumerate(reader, 1):
            if None in row or any(value is None for value in row.values()):
                raise ValueError(f"{path}: malformed vtable TSV record {row_index}")
            rows.append(row)
    return _sha256(path.read_bytes()), rows


def build_object_role_feature_set(
    effect_rows: list[dict[str, Any]],
    *,
    effect_ir_sha256: str,
    receiver_rows: list[dict[str, Any]] | None = None,
    receiver_sha256: str | None = None,
    vtable_rows: list[dict[str, str]] | None = None,
    vtable_sha256: str | None = None,
    callgraph_rows: list[dict[str, Any]] | None = None,
    callgraph_sha256: str | None = None,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Project existing generic evidence into group-scoped opaque hashes."""
    if not effect_rows:
        raise ValueError("FunctionEffectIR input must not be empty")
    validate_function_effect_ir(effect_rows, effect_ir_sha256)
    for name, rows, digest in (
        ("receiver inference", receiver_rows, receiver_sha256),
        ("vtable slots", vtable_rows, vtable_sha256),
        ("callgraph metrics", callgraph_rows, callgraph_sha256),
    ):
        if (rows is None) != (digest is None):
            raise ValueError(f"{name}: rows and source SHA-256 must be supplied together")
        if digest is not None and (
            not isinstance(digest, str) or len(digest) != 64
            or set(digest) - set("0123456789abcdef")
        ):
            raise ValueError(f"{name}: invalid SHA-256")

    program_ids = {row["program_id"] for row in effect_rows}
    if len(program_ids) != 1:
        raise ValueError("FunctionEffectIR input contains multiple program ids")
    program_id = next(iter(program_ids))
    function_features: dict[str, dict[tuple[str, str], set[tuple[str, str, int]]]] = defaultdict(
        lambda: defaultdict(set)
    )

    def add_feature(
        function_entry: str,
        group: str,
        value: str,
        source_format: str,
        source_sha256: str,
        source_record_index: int,
    ) -> None:
        feature_sha = hashlib.sha256(f"{group}\0{value}".encode("utf-8")).hexdigest()
        function_features[function_entry][(group, feature_sha)].add(
            (source_format, source_sha256, source_record_index)
        )

    direct_calls = []
    for row_index, record in enumerate(effect_rows, 1):
        function_entry = record["function_entry"]
        function_features[function_entry]
        for effect in record["effects"]:
            kind = effect["kind"]
            provenance = effect["provenance"]
            support = (
                provenance["source_format"], provenance["artifact_sha256"], provenance["record_index"]
            )
            add_feature(function_entry, "effect_ir", f"kind:{kind}", *support)
            if kind in {"parameter_field_read", "parameter_field_write"}:
                offset = int(effect["field_offset"], 0)
                width = effect["value_size"] if effect["value_size"] is not None else "unknown"
                value = f"{kind}:parameter:{effect['parameter_index']}:offset:{offset}:width:{width}"
                add_feature(function_entry, "field", value, *support)
            if (
                kind == "direct_call"
                and isinstance(effect["target_entry"], str)
                and effect["target_entry"] not in {"", "-"}
            ):
                direct_calls.append((function_entry, effect["target_entry"], support))

    receiver_count = 0
    seen_receiver_calls = set()
    for row_index, row in enumerate(receiver_rows or [], 1):
        if not isinstance(row, dict):
            raise ValueError(f"receiver inference row {row_index}: expected an object")
        if row.get("format") != RECEIVER_FORMAT:
            raise ValueError(f"receiver inference row {row_index}: unsupported format")
        function_entry, source_id = row.get("source_entry"), row.get("source_id")
        call_index, status = row.get("call_index"), row.get("status")
        if (
            not isinstance(function_entry, str) or not function_entry
            or not isinstance(source_id, str) or not source_id
        ):
            raise ValueError(f"receiver inference row {row_index}: invalid function identity")
        if isinstance(call_index, bool) or not isinstance(call_index, int) or call_index < 0:
            raise ValueError(f"receiver inference row {row_index}: invalid call_index")
        if not isinstance(status, str) or status not in RECEIVER_STATUSES:
            raise ValueError(f"receiver inference row {row_index}: unsupported status")
        identity = (source_id, call_index)
        if identity in seen_receiver_calls:
            raise ValueError(f"receiver inference row {row_index}: duplicate source_id/call_index")
        seen_receiver_calls.add(identity)
        receiver_count += 1
        if status != "resolved_unique_vtable":
            continue
        receiver_vtable_id = row.get("receiver_vtable_id")
        if not isinstance(receiver_vtable_id, str) or not receiver_vtable_id:
            raise ValueError(f"receiver inference row {row_index}: resolved status lacks a vtable id")
        add_feature(function_entry, "receiver", receiver_vtable_id, RECEIVER_FORMAT, receiver_sha256 or "", row_index)

    vtable_count = 0
    for row_index, row in enumerate(vtable_rows or [], 1):
        if (
            not isinstance(row, dict) or set(row) != set(VTABLE_HEADER)
            or any(not isinstance(value, str) for value in row.values())
        ):
            raise ValueError(f"vtable row {row_index}: unexpected fields or non-string value")
        resolution_mode = row["resolution_mode"]
        if resolution_mode not in VTABLE_RESOLUTION_MODES:
            raise ValueError(f"vtable row {row_index}: unsupported resolution_mode")
        if row["target_thumb"] not in {"true", "false"}:
            raise ValueError(f"vtable row {row_index}: invalid target_thumb")
        vtable_count += 1
        target_entry = row.get("target_entry", "")
        if not target_entry or target_entry == "-" or resolution_mode == "unexpected":
            continue
        slot_offset = row.get("slot_offset", "")
        if _OFFSET.fullmatch(slot_offset) is None:
            raise ValueError(f"vtable row {row_index}: invalid slot_offset")
        add_feature(
            target_entry, "vtable_slot", f"slot_offset_bytes:{int(slot_offset, 16)}",
            VTABLE_FORMAT, vtable_sha256 or "", row_index,
        )

    callgraph_count = 0
    for row_index, row in enumerate(callgraph_rows or [], 1):
        if not isinstance(row, dict):
            raise ValueError(f"callgraph metrics row {row_index}: expected an object")
        if row.get("format") != CALLGRAPH_FORMAT:
            raise ValueError(f"callgraph metrics row {row_index}: unsupported format")
        record_id, function_entry, metrics = row.get("id"), row.get("source_entry"), row.get("metrics")
        if (
            not isinstance(record_id, str) or not record_id
            or not isinstance(function_entry, str) or not function_entry
            or not isinstance(metrics, dict)
        ):
            raise ValueError(f"callgraph metrics row {row_index}: invalid function or metrics")
        callgraph_count += 1
        for metric_name in ("fan_in", "fan_out"):
            value = metrics.get(metric_name)
            if value is None:
                continue
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"callgraph metrics row {row_index}: invalid {metric_name}")
            add_feature(
                function_entry, "callgraph", f"{metric_name}:{count_bucket(value)}",
                CALLGRAPH_FORMAT, callgraph_sha256 or "", row_index,
            )

    for caller, callee, support in direct_calls:
        add_feature(caller, "callgraph", f"out:{callee}", *support)
        if callee in function_features:
            add_feature(callee, "callgraph", f"in:{caller}", *support)

    feature_rows = []
    feature_count = 0
    for function_entry in sorted(function_features):
        features = []
        for (group, feature_sha), support_rows in sorted(function_features[function_entry].items()):
            features.append({
                "group": group,
                "feature_sha256": feature_sha,
                "support": [
                    {"source_format": source_format, "source_sha256": source_sha, "source_record_index": source_index}
                    for source_format, source_sha, source_index in sorted(support_rows)
                ],
            })
        feature_count += len(features)
        feature_rows.append({
            "format": FEATURE_FORMAT,
            "program_id": program_id,
            "function_entry": function_entry,
            "features": features,
        })

    manifest = {
        "format": MANIFEST_FORMAT,
        "program_id": program_id,
        "input_artifacts": {
            "function_effect_ir": {"sha256": effect_ir_sha256, "row_count": len(effect_rows)},
            "receiver_inference": {"sha256": receiver_sha256, "row_count": receiver_count},
            "vtable_slots": {"sha256": vtable_sha256, "row_count": vtable_count},
            "callgraph_metrics": {"sha256": callgraph_sha256, "row_count": callgraph_count},
        },
        "function_count": len(feature_rows),
        "feature_count": feature_count,
    }
    return feature_rows, manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("function_effect_ir_jsonl", type=Path)
    parser.add_argument("--receiver-inference", type=Path)
    parser.add_argument("--vtable-slots-tsv", type=Path)
    parser.add_argument("--callgraph-metrics", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    manifest_path = args.output.with_suffix(args.output.suffix + ".manifest.json")
    input_paths = [path for path in (
        args.function_effect_ir_jsonl, args.receiver_inference,
        args.vtable_slots_tsv, args.callgraph_metrics,
    ) if path is not None]
    output_paths = {args.output.resolve(), manifest_path.resolve()}
    if any(path.resolve() in output_paths for path in input_paths):
        raise ValueError("output path overlaps an input artifact")

    effect_sha, effect_rows = _read_jsonl(args.function_effect_ir_jsonl)
    receiver_sha, receiver_rows = _read_jsonl(args.receiver_inference) if args.receiver_inference else (None, None)
    vtable_sha, vtable_rows = _read_vtable_tsv(args.vtable_slots_tsv) if args.vtable_slots_tsv else (None, None)
    callgraph_sha, callgraph_rows = _read_jsonl(args.callgraph_metrics) if args.callgraph_metrics else (None, None)
    feature_rows, manifest = build_object_role_feature_set(
        effect_rows,
        effect_ir_sha256=effect_sha,
        receiver_rows=receiver_rows,
        receiver_sha256=receiver_sha,
        vtable_rows=vtable_rows,
        vtable_sha256=vtable_sha,
        callgraph_rows=callgraph_rows,
        callgraph_sha256=callgraph_sha,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for row in feature_rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("functions:", manifest["function_count"])
    print("features:", manifest["feature_count"])
    print("output:", args.output)
    print("manifest:", manifest_path)
    return 0
