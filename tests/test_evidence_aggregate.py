from __future__ import annotations

import csv
import json
from pathlib import Path

from revenginstr.evidence.aggregate import aggregate


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def test_evidence_aggregate_excludes_raw_class_identity(tmp_path: Path) -> None:
    trace = tmp_path / "trace.jsonl"
    callgraph = tmp_path / "callgraph.jsonl"
    receivers = tmp_path / "receivers.tsv"
    inference = tmp_path / "inference.jsonl"
    write_jsonl(trace, [
        {"id": "f1", "program": "sample.so", "source_entry": "1000"},
        {"id": "f2", "program": "sample.so", "source_entry": "2000"},
    ])
    write_jsonl(callgraph, [
        {"format": "REVENGINSTR.CallGraphMetrics/1", "id": "f1", "metrics": {"fan_in": 2, "fan_out": 3}},
        {"format": "REVENGINSTR.CallGraphMetrics/1", "id": "f2", "metrics": {"fan_in": 1, "fan_out": 0}},
    ])
    fields = [
        "format", "source_id", "call_index", "receiver_present", "receiver_storage_kind",
        "receiver_pointer_depth", "pointee_type_display", "flow_single_pointer_pointee_displays_json",
    ]
    with receivers.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, delimiter="\t")
        writer.writeheader()
        writer.writerow({
            "format": "REVENGINSTR.GhidraIndirectReceiverType/1",
            "source_id": "sample.so:1000",
            "call_index": "0",
            "receiver_present": "1",
            "receiver_storage_kind": "register",
            "receiver_pointer_depth": "1",
            "pointee_type_display": "SecretClass",
            "flow_single_pointer_pointee_displays_json": json.dumps(["SecretClass"]),
        })
    write_jsonl(inference, [{
        "format": "REVENGINSTR.ReceiverInference/1",
        "source_id": "sample.so:1000",
        "call_index": 0,
        "status": "resolved_unique_vtable",
        "class_name": "SecretClass",
        "class_evidence_source": "direct_receiver_type",
        "candidate_receiver_class_names": ["SecretClass"],
        "receiver_vtable_id": "secret-vtable",
        "dispatch_slot_offset": None,
    }])

    rows, stats = aggregate(trace, [callgraph], receivers, inference)
    indexed = {row["id"]: row for row in rows}
    features = indexed["f1"]["features"]
    assert indexed["f1"]["format"] == "REVENGINSTR.Evidence/1"
    assert features["has_callgraph"] == 1.0
    assert features["callgraph.fan_in"] == 2.0
    assert features["has_receiver_types"] == 1.0
    assert features["has_receiver_inference"] == 1.0
    assert features["receiver.resolved_count"] == 1.0
    assert features["receiver.evidence_direct_receiver_type_count"] == 1.0
    assert features["receiver.candidate_class_total"] == 1.0
    serialized = json.dumps(rows)
    assert "SecretClass" not in serialized
    assert "secret-vtable" not in serialized
    assert stats["receiver_inference"]["matched"] == 1


def test_evidence_aggregate_keeps_uncovered_rows(tmp_path: Path) -> None:
    trace = tmp_path / "trace.jsonl"
    write_jsonl(trace, [{"id": "f1", "program": "x", "source_entry": "10"}])
    rows, stats = aggregate(trace, [], None, None)
    assert stats == {}
    assert rows == [{"format": "REVENGINSTR.Evidence/1", "id": "f1", "features": {}}]
