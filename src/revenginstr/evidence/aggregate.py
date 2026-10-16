#!/usr/bin/env python3
"""Aggregate project-neutral callgraph and receiver evidence into safe numeric features."""
from __future__ import annotations

import argparse
import csv
import json
import math
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable

FORMAT = "REVENGINSTR.Evidence/1"
INFERENCE_FORMAT = "REVENGINSTR.ReceiverInference/1"
RESOLVED_STATUSES = {"resolved_unique_vtable", "resolved_unique_vtable_runtime_match"}
MISSING = {"", "-", "<missing>", None}


def read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line_no, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            row = json.loads(raw)
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_no}: expected JSON object")
            yield row


def safe_key(value: Any) -> str:
    text = str(value or "missing").strip().lower()
    text = re.sub(r"[^a-z0-9_]+", "_", text).strip("_")
    return text or "missing"


def number(value: Any) -> float | None:
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)) and math.isfinite(float(value)):
        return float(value)
    if isinstance(value, str):
        try:
            parsed = float(value)
        except ValueError:
            try:
                parsed = float(int(value, 0))
            except ValueError:
                return None
        return parsed if math.isfinite(parsed) else None
    return None


def int_cell(value: Any, default: int = 0) -> int:
    if value in MISSING:
        return default
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return default


def json_list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if not isinstance(value, str) or not value.strip():
        return []
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return []
    return parsed if isinstance(parsed, list) else []


def load_trace(path: Path) -> tuple[dict[str, str], set[str]]:
    source_to_id: dict[str, str] = {}
    ids: set[str] = set()
    for row in read_jsonl(path):
        record_id = row.get("id")
        program = row.get("program")
        entry = row.get("source_entry")
        if not all(isinstance(item, str) and item for item in (record_id, program, entry)):
            continue
        source_id = f"{program}:{entry}"
        previous = source_to_id.get(source_id)
        if previous is not None and previous != record_id:
            raise ValueError(f"trace has conflicting ids for {source_id}")
        source_to_id[source_id] = record_id
        ids.add(record_id)
    if not ids:
        raise ValueError(f"{path}: no usable trace rows")
    return source_to_id, ids


def resolve_id(raw: Any, source_to_id: dict[str, str], ids: set[str]) -> str | None:
    if not isinstance(raw, str) or not raw:
        return None
    if raw in ids:
        return raw
    return source_to_id.get(raw)


def add(target: dict[str, float], key: str, value: Any, mode: str = "set") -> None:
    numeric = number(value)
    if numeric is None:
        return
    if mode == "sum":
        target[key] = target.get(key, 0.0) + numeric
    elif mode == "max":
        target[key] = max(target.get(key, numeric), numeric)
    else:
        target[key] = numeric


def merge_metric_files(paths: list[Path], source_to_id: dict[str, str], ids: set[str],
                       features: dict[str, dict[str, float]], prefix: str) -> Counter:
    stats: Counter = Counter()
    for path in paths:
        for row in read_jsonl(path):
            record_id = resolve_id(row.get("id"), source_to_id, ids)
            if record_id is None:
                stats["unmatched"] += 1
                continue
            metrics = row.get("metrics")
            if not isinstance(metrics, dict):
                stats["missing_metrics"] += 1
                continue
            target = features[record_id]
            target[f"has_{prefix}"] = 1.0
            for key, value in metrics.items():
                add(target, f"{prefix}.{safe_key(key)}", value)
            stats["matched"] += 1
    return stats


def merge_receiver_types(path: Path, source_to_id: dict[str, str], ids: set[str],
                         features: dict[str, dict[str, float]]) -> Counter:
    stats: Counter = Counter()
    with path.open("r", encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle, delimiter="\t"):
            record_id = resolve_id(row.get("source_id"), source_to_id, ids)
            if record_id is None:
                stats["unmatched"] += 1
                continue
            target = features[record_id]
            target["has_receiver_types"] = 1.0
            add(target, "receiver.call_count", 1, "sum")
            add(target, "receiver.present_count", int_cell(row.get("receiver_present")), "sum")
            depth = int_cell(row.get("receiver_pointer_depth"))
            add(target, "receiver.pointer_depth_sum", depth, "sum")
            add(target, "receiver.pointer_depth_max", depth, "max")
            add(target, f"receiver.pointer_depth_{min(max(depth, 0), 4)}_count", 1, "sum")
            add(target, f"receiver.storage_{safe_key(row.get('receiver_storage_kind'))}_count", 1, "sum")
            direct = row.get("pointee_type_display")
            if depth == 1 and direct not in MISSING and str(direct).strip() != "void":
                add(target, "receiver.direct_single_pointer_count", 1, "sum")
            flow = sorted({str(item) for item in json_list(row.get("flow_single_pointer_pointee_displays_json")) if item not in MISSING})
            add(target, "receiver.flow_candidate_total", len(flow), "sum")
            add(target, "receiver.flow_candidate_max", len(flow), "max")
            if len(flow) == 1:
                add(target, "receiver.flow_unique_count", 1, "sum")
            elif len(flow) > 1:
                add(target, "receiver.flow_ambiguous_count", 1, "sum")
            stats["matched"] += 1
    return stats


def slot_bucket(value: Any) -> str:
    offset = int_cell(value, -1)
    if offset < 0:
        return "missing"
    if offset < 0x20:
        return "lt20"
    if offset < 0x80:
        return "20_7f"
    if offset < 0x200:
        return "80_1ff"
    return "200_plus"


def merge_receiver_inference(path: Path, source_to_id: dict[str, str], ids: set[str],
                             features: dict[str, dict[str, float]]) -> Counter:
    stats: Counter = Counter()
    for row in read_jsonl(path):
        if row.get("format") != INFERENCE_FORMAT:
            stats["foreign_format"] += 1
            continue
        record_id = resolve_id(row.get("source_id"), source_to_id, ids)
        if record_id is None:
            stats["unmatched"] += 1
            continue
        target = features[record_id]
        target["has_receiver_inference"] = 1.0
        add(target, "receiver.inference_count", 1, "sum")
        status = safe_key(row.get("status"))
        add(target, f"receiver.status_{status}_count", 1, "sum")
        if row.get("status") in RESOLVED_STATUSES:
            add(target, "receiver.resolved_count", 1, "sum")
        if row.get("status") == "resolved_unique_vtable_runtime_match":
            add(target, "receiver.runtime_match_count", 1, "sum")
        if row.get("status") == "non_virtual_indirect_call":
            add(target, "receiver.non_virtual_count", 1, "sum")
        source = row.get("class_evidence_source")
        if isinstance(source, str) and source:
            add(target, f"receiver.evidence_{safe_key(source)}_count", 1, "sum")
        candidates = row.get("candidate_receiver_class_names")
        if not isinstance(candidates, list):
            candidates = []
        add(target, "receiver.candidate_class_total", len(candidates), "sum")
        add(target, "receiver.candidate_class_max", len(candidates), "max")
        add(target, f"receiver.slot_{slot_bucket(row.get('dispatch_slot_offset'))}_count", 1, "sum")
        stats["matched"] += 1
    return stats


def aggregate(trace: Path, callgraph: list[Path], receiver_types: Path | None,
              receiver_inference: Path | None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    source_to_id, ids = load_trace(trace)
    features: dict[str, dict[str, float]] = defaultdict(dict)
    stats: dict[str, Any] = {}
    if callgraph:
        stats["callgraph"] = dict(merge_metric_files(callgraph, source_to_id, ids, features, "callgraph"))
    if receiver_types is not None:
        stats["receiver_types"] = dict(merge_receiver_types(receiver_types, source_to_id, ids, features))
    if receiver_inference is not None:
        stats["receiver_inference"] = dict(merge_receiver_inference(receiver_inference, source_to_id, ids, features))
    rows = [
        {"format": FORMAT, "id": record_id, "features": dict(sorted(features.get(record_id, {}).items()))}
        for record_id in sorted(ids)
    ]
    return rows, stats


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("--callgraph-metrics", type=Path, action="append", default=[])
    parser.add_argument("--receiver-types", type=Path)
    parser.add_argument("--receiver-inference", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    rows, stats = aggregate(args.trace, args.callgraph_metrics, args.receiver_types, args.receiver_inference)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    covered = sum(bool(row["features"]) for row in rows)
    feature_keys = {key for row in rows for key in row["features"]}
    print("format:", FORMAT)
    print("dataset functions:", len(rows))
    print("functions with external evidence:", covered)
    print("coverage:", round(covered / len(rows), 6) if rows else 0.0)
    print("feature keys:", len(feature_keys))
    print("sources:", json.dumps(stats, sort_keys=True))
    print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
