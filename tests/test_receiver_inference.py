from __future__ import annotations

import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator

from revenginstr.receiver.infer import (
    PRIMARY_FAILURE_REASON_CODES,
    TRANSPARENT_RECEIVER_FLOW_OPS,
    infer,
    infer_with_candidate_assessments,
    infer_with_failure_reasons,
    main,
)


SCHEMA = Path(__file__).resolve().parents[1] / "schemas" / "receiver-failure-reason-v1.schema.json"


def test_failure_reason_transparent_operations_match_receiver_exporter() -> None:
    root = Path(__file__).resolve().parents[1]
    source = (root / "ghidra/ExportIndirectCallReceiverTypes.java").read_text(encoding="utf-8")
    method = source.split("private void collectTransparentTypeEvidence", 1)[1]
    method = method.split("private String jsonString", 1)[0]
    exporter_operations = set(re.findall(r"PcodeOp\.([A-Z0-9_]+)", method))

    assert exporter_operations == TRANSPARENT_RECEIVER_FLOW_OPS


def test_receiver_inference_resolves_unique_direct_type() -> None:
    receiver_rows = [{
        "format": "REVENGINSTR.GhidraIndirectReceiverType/1",
        "source_id": "sample.exe:1000",
        "call_index": "0",
        "call_address": "1010",
        "receiver_pointer_depth": "1",
        "pointee_type_name": "Vehicle",
        "pointee_type_display": "class Game::Vehicle",
        "receiver_type_name": "Vehicle *",
        "receiver_type_display": "Game::Vehicle *",
        "receiver_storage_kind": "register",
        "flow_type_node_count": "1",
        "flow_single_pointer_pointee_names_json": "[]",
        "flow_single_pointer_pointee_displays_json": "[]",
    }]
    catalog = [{
        "format": "consumer.catalog/7",
        "class_name": "Game::Vehicle",
        "receiver_vtable_id": "vtbl:vehicle",
    }]
    rows = infer(receiver_rows, catalog)
    assert len(rows) == 1
    row = rows[0]
    assert row["format"] == "REVENGINSTR.ReceiverInference/1"
    assert row["status"] == "resolved_unique_vtable"
    assert row["class_name"] == "Game::Vehicle"
    assert row["receiver_vtable_id"] == "vtbl:vehicle"
    assert "primary_failure_reason" not in row
    assert row["affects_routing"] is False
    assert row["dispatch_slot_offset"] is None


def test_receiver_inference_uses_unique_terminal_name() -> None:
    receiver_rows = [{
        "format": "legacy.receiver/2",
        "source_id": "sample:2000",
        "call_index": "1",
        "receiver_pointer_depth": "1",
        "pointee_type_name": "Vehicle",
        "pointee_type_display": "struct Vehicle",
        "receiver_storage_kind": "unique",
        "flow_type_node_count": "0",
        "flow_single_pointer_pointee_names_json": "[]",
        "flow_single_pointer_pointee_displays_json": "[]",
    }]
    catalog = [{"class_name": "Namespace::Vehicle", "receiver_vtable_id": "v1"}]
    row = infer(receiver_rows, catalog)[0]
    assert row["status"] == "resolved_unique_vtable"
    assert row["class_match_kind"] == "unique_terminal_class_name"


def test_receiver_inference_rejects_ambiguous_terminal_name() -> None:
    receiver_rows = [{
        "source_id": "sample:3000",
        "call_index": "0",
        "receiver_pointer_depth": "1",
        "pointee_type_name": "Vehicle",
        "pointee_type_display": "Vehicle",
        "flow_type_node_count": "0",
        "flow_single_pointer_pointee_names_json": "[]",
        "flow_single_pointer_pointee_displays_json": "[]",
    }]
    catalog = [
        {"class_name": "A::Vehicle", "receiver_vtable_id": "a"},
        {"class_name": "B::Vehicle", "receiver_vtable_id": "b"},
    ]
    row = infer(receiver_rows, catalog)[0]
    assert row["status"] == "unresolved_receiver_class"
    assert "primary_failure_reason" not in row
    assert row["receiver_vtable_id"] is None


def test_receiver_inference_detects_multi_vtable_class() -> None:
    receiver_rows = [{
        "source_id": "sample:4000",
        "call_index": "0",
        "receiver_pointer_depth": "1",
        "pointee_type_display": "Game::Vehicle",
        "flow_type_node_count": "0",
        "flow_single_pointer_pointee_names_json": "[]",
        "flow_single_pointer_pointee_displays_json": "[]",
    }]
    catalog = [
        {"class_name": "Game::Vehicle", "receiver_vtable_id": "v1"},
        {"class_name": "Game::Vehicle", "receiver_vtable_id": "v2"},
    ]
    row = infer(receiver_rows, catalog)[0]
    assert row["status"] == "ambiguous_class_vtable"
    assert row["candidate_receiver_vtable_ids"] == ["v1", "v2"]

def test_receiver_failure_reasons_cover_observable_residuals() -> None:
    receiver_rows = [
        {
            "source_id": "sample:5000", "call_index": "0", "receiver_pointer_depth": "1",
            "pointee_type_name": "UnknownType", "flow_single_pointer_pointee_names_json": "[]",
            "flow_single_pointer_pointee_displays_json": "[]",
        },
        {
            "source_id": "sample:6000", "call_index": "0", "receiver_pointer_depth": "1",
            "flow_single_pointer_pointee_names_json": "[]",
            "flow_single_pointer_pointee_displays_json": "[]",
        },
        {
            "source_id": "sample:7000", "call_index": "0", "receiver_pointer_depth": "2",
            "flow_single_pointer_pointee_names_json": "[]",
            "flow_single_pointer_pointee_displays_json": "[]",
        },
        {
            "format": "REVENGINSTR.GhidraIndirectReceiverType/1",
            "source_id": "sample:b000", "call_index": "0", "receiver_present": "0",
            "receiver_pointer_depth": "0", "flow_single_pointer_pointee_names_json": "[]",
            "flow_single_pointer_pointee_displays_json": "[]",
        },
        {
            "format": "other-format", "source_id": "sample:c000", "call_index": "0",
            "receiver_present": "0", "receiver_pointer_depth": "0",
            "flow_single_pointer_pointee_names_json": "[]",
            "flow_single_pointer_pointee_displays_json": "[]",
        },
        {
            "format": "REVENGINSTR.GhidraIndirectReceiverType/1",
            "source_id": "sample:d000", "call_index": "0", "receiver_pointer_depth": "1",
            "receiver_token": "def:PTRSUB@1000:7:4",
            "flow_single_pointer_pointee_names_json": "[]",
            "flow_single_pointer_pointee_displays_json": "[]",
        },
        {
            "format": "REVENGINSTR.GhidraIndirectReceiverType/1",
            "source_id": "sample:e000", "call_index": "0", "receiver_pointer_depth": "1",
            "receiver_token": "def:MULTIEQUAL@2000:5:4",
            "flow_single_pointer_pointee_names_json": "[]",
            "flow_single_pointer_pointee_displays_json": "[]",
        },
        {
            "format": "REVENGINSTR.GhidraIndirectReceiverType/1",
            "source_id": "sample:g000", "call_index": "0", "receiver_pointer_depth": "1",
            "receiver_token": "def:MULTIEQUAL@4000:3:4",
            "flow_single_pointer_pointee_names_json": "[\"Fixture::Left\",\"Fixture::Right\"]",
            "flow_single_pointer_pointee_displays_json": "[]",
        },
        {
            "format": "REVENGINSTR.GhidraIndirectReceiverType/1",
            "source_id": "sample:h000", "call_index": "0", "receiver_pointer_depth": "1",
            "receiver_token": "def:INT_ADD@5000:3:4",
            "flow_single_pointer_pointee_names_json": "[\"Fixture::Left\",\"Fixture::Right\"]",
            "flow_single_pointer_pointee_displays_json": "[]",
        },
        {
            "format": "other-format", "source_id": "sample:f000", "call_index": "0",
            "receiver_pointer_depth": "1", "receiver_token": "def:PTRSUB@3000:7:4",
            "flow_single_pointer_pointee_names_json": "[]",
            "flow_single_pointer_pointee_displays_json": "[]",
        },
        {
            "source_id": "sample:8000", "call_index": "0", "receiver_pointer_depth": "1",
            "pointee_type_name": "Vehicle", "flow_single_pointer_pointee_names_json": "[]",
            "flow_single_pointer_pointee_displays_json": "[]",
        },
        {
            "source_id": "sample:9000", "call_index": "0", "receiver_pointer_depth": "1",
            "pointee_type_name": "Game::Multi", "flow_single_pointer_pointee_names_json": "[]",
            "flow_single_pointer_pointee_displays_json": "[]",
        },
        {
            "source_id": "sample:a000", "call_index": "0", "receiver_pointer_depth": "1",
            "pointee_type_name": "Game::Known", "flow_single_pointer_pointee_names_json": "[\"Game::Other\"]",
            "flow_single_pointer_pointee_displays_json": "[]",
        },
    ]
    catalog = [
        {"class_name": "KnownType", "receiver_vtable_id": "v1"},
        {"class_name": "A::Vehicle", "receiver_vtable_id": "a"},
        {"class_name": "B::Vehicle", "receiver_vtable_id": "b"},
        {"class_name": "Game::Known", "receiver_vtable_id": "known"},
        {"class_name": "Game::Other", "receiver_vtable_id": "other"},
        {"class_name": "Game::Multi", "receiver_vtable_id": "m1"},
        {"class_name": "Game::Multi", "receiver_vtable_id": "m2"},
        {"class_name": "Fixture::Left", "receiver_vtable_id": "left"},
        {"class_name": "Fixture::Right", "receiver_vtable_id": "right"},
    ]

    rows, failures = infer_with_failure_reasons(receiver_rows, catalog)

    assert len(rows) == 13
    assert [row["primary_failure_reason"] for row in failures] == [
        "missing_vtable_catalog_entry",
        "insufficient_receiver_type_evidence",
        "receiver_not_single_pointer",
        "non_virtual_call_indirect",
        "receiver_not_single_pointer",
        "unsupported_pattern",
        "insufficient_receiver_type_evidence",
        "ambiguous_phi",
        "mixed_receiver_candidates",
        "insufficient_receiver_type_evidence",
        "mixed_receiver_candidates",
        "ambiguous_receiver_vtable",
        "mixed_receiver_candidates",
    ]
    assert rows[-1]["status"] == "ambiguous_receiver_class"
    schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    for row in failures:
        validator.validate(row)
    assert set(schema["properties"]["primary_failure_reason"]["enum"]) == PRIMARY_FAILURE_REASON_CODES
    assert {row["primary_failure_reason"] for row in failures} <= PRIMARY_FAILURE_REASON_CODES
    assert all("primary_failure_reason" not in row for row in rows)


def test_failure_reason_sidecar_only_contains_unresolved_rows() -> None:
    receiver_rows = [{
        "source_id": "sample:1000",
        "call_index": "0",
        "receiver_pointer_depth": "1",
        "pointee_type_name": "Widget",
        "flow_single_pointer_pointee_names_json": "[]",
        "flow_single_pointer_pointee_displays_json": "[]",
    }]
    catalog = [{"class_name": "Widget", "receiver_vtable_id": "v1"}]

    rows, failures = infer_with_failure_reasons(receiver_rows, catalog)

    assert rows[0]["status"] == "resolved_unique_vtable"
    assert failures == []


def test_receiver_inference_cli_writes_optional_reason_sidecar(tmp_path: Path) -> None:
    receiver_types = tmp_path / "receiver-types.tsv"
    receiver_types.write_text(
        "format\tsource_id\tcall_index\tcall_address\treceiver_present\t"
        "receiver_pointer_depth\treceiver_token\t"
        "pointee_type_name\tflow_single_pointer_pointee_names_json\t"
        "flow_single_pointer_pointee_displays_json\n"
        "REVENGINSTR.GhidraIndirectReceiverType/1\tsample:1000\t0\t1010\t1\t"
        "1\tdef:INT_ADD@1010:2:4\tUnknownType\t[]\t[]\n"
        "REVENGINSTR.GhidraIndirectReceiverType/1\tsample:2000\t0\t2020\t0\t"
        "0\t0\t-\t[]\t[]\n"
        "REVENGINSTR.GhidraIndirectReceiverType/1\tsample:3000\t0\t3030\t1\t"
        "1\tdef:PTRSUB@3030:3:4\t-\t[]\t[]\n",
        encoding="utf-8",
    )
    catalog = tmp_path / "catalog.jsonl"
    catalog.write_text(
        '{"class_name":"KnownType","receiver_vtable_id":"v1"}\n', encoding="utf-8"
    )
    output = tmp_path / "inference.jsonl"
    failures_path = tmp_path / "failure-reasons.jsonl"

    assert main([
        str(receiver_types), str(catalog), "--output", str(output),
        "--failure-reasons-output", str(failures_path),
    ]) == 0

    inference_rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    failure_rows = [json.loads(line) for line in failures_path.read_text(encoding="utf-8").splitlines()]
    assert [row["status"] for row in inference_rows] == [
        "unresolved_receiver_class", "receiver_not_single_pointer", "unresolved_receiver_class",
    ]
    assert all("primary_failure_reason" not in row for row in inference_rows)
    assert [row["primary_failure_reason"] for row in failure_rows] == [
        "missing_vtable_catalog_entry", "non_virtual_call_indirect", "unsupported_pattern",
    ]
    validator = Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")))
    for row in failure_rows:
        validator.validate(row)


def test_candidate_assessment_distinguishes_convergence_compatibility_and_unknowns() -> None:
    def row(
        source_id: str, direct_type: str | None, flow_types: list[str] | None = None
    ) -> dict[str, str]:
        flow_types = flow_types or []
        return {
            "source_id": source_id,
            "call_index": "0",
            "call_address": "1010",
            "receiver_pointer_depth": "1",
            "pointee_type_name": direct_type or "",
            "pointee_type_display": direct_type or "",
            "flow_type_node_count": str(len(flow_types)),
            "flow_single_pointer_pointee_names_json": json.dumps(flow_types),
            "flow_single_pointer_pointee_displays_json": json.dumps(flow_types),
        }

    receiver_rows = [
        row("sample:same", "Game::Base"),
        row("sample:compatible", "Game::Base", ["Game::Derived"]),
        row("sample:mixed", "Game::A", ["Game::B"]),
        row("sample:partial", "Game::Base", ["UnknownType"]),
        row("sample:partial-compatible", "Game::Base", ["Game::Derived", "UnknownType"]),
        row("sample:terminal", "Vehicle"),
        row("sample:unknown", "UnknownOnly"),
    ]
    catalog = [
        {"class_name": "Game::Base", "receiver_vtable_id": "base", "receiver_compatibility_group_id": "family:vehicle"},
        {"class_name": "Game::Derived", "receiver_vtable_id": "derived", "receiver_compatibility_group_id": "family:vehicle"},
        {"class_name": "Game::A", "receiver_vtable_id": "a", "receiver_compatibility_group_id": "family:a"},
        {"class_name": "Game::B", "receiver_vtable_id": "b", "receiver_compatibility_group_id": "family:b"},
        {"class_name": "A::Vehicle", "receiver_vtable_id": "vehicle-a"},
        {"class_name": "B::Vehicle", "receiver_vtable_id": "vehicle-b"},
    ]

    inference_rows, assessments = infer_with_candidate_assessments(receiver_rows, catalog)

    assert len(inference_rows) == len(assessments) == 7
    assert [row["status"] for row in inference_rows] == [
        "resolved_unique_vtable",
        "ambiguous_receiver_class",
        "ambiguous_receiver_class",
        "resolved_unique_vtable",
        "ambiguous_receiver_class",
        "unresolved_receiver_class",
        "unresolved_receiver_class",
    ]
    assert [row["status"] for row in assessments] == [
        "same_type_convergence",
        "compatible_subtype_candidates",
        "mixed_candidates",
        "partially_unknown_candidates",
        "partially_unknown_candidates",
        "mixed_candidates",
        "no_known_candidates",
    ]
    assert assessments[1]["compatibility_group_id"] == "family:vehicle"
    assert assessments[3]["unknown_type_candidate_count"] == 1
    assert assessments[4]["candidate_receiver_class_names"] == ["Game::Base", "Game::Derived"]
    assert assessments[4]["unknown_type_candidate_count"] == 1
    assert assessments[4]["compatibility_group_id"] == "family:vehicle"
    assert assessments[5]["candidate_receiver_class_names"] == ["A::Vehicle", "B::Vehicle"]
    assert assessments[6]["unknown_type_candidate_count"] == 1
    assert all("candidate_assessment" not in row for row in inference_rows)

    assessment_schema = json.loads(
        (SCHEMA.parent / "receiver-candidate-assessment-v1.schema.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(assessment_schema)
    for assessment in assessments:
        validator.validate(assessment)

    conflicting_catalog = catalog + [{
        "class_name": "Game::Base",
        "receiver_vtable_id": "base-alternate",
        "receiver_compatibility_group_id": "family:other",
    }]
    _rows, conflicting_assessments = infer_with_candidate_assessments(
        [receiver_rows[1]], conflicting_catalog
    )
    assert conflicting_assessments[0]["status"] == "mixed_candidates"
    assert conflicting_assessments[0]["compatibility_group_id"] is None


def test_receiver_inference_cli_writes_optional_candidate_assessment(tmp_path: Path) -> None:
    receiver_types = tmp_path / "receiver-types.tsv"
    receiver_types.write_text(
        "format\tsource_id\tcall_index\tcall_address\treceiver_pointer_depth\t"
        "pointee_type_name\tpointee_type_display\tflow_type_node_count\t"
        "flow_single_pointer_pointee_names_json\tflow_single_pointer_pointee_displays_json\n"
        "REVENGINSTR.GhidraIndirectReceiverType/1\tsample:1000\t0\t1010\t1\t"
        "Game::Widget\tGame::Widget\t0\t[]\t[]\n",
        encoding="utf-8",
    )
    catalog = tmp_path / "catalog.jsonl"
    catalog.write_text(
        '{"class_name":"Game::Widget","receiver_vtable_id":"v1"}\n',
        encoding="utf-8",
    )
    output = tmp_path / "inference.jsonl"
    assessment_output = tmp_path / "assessment.jsonl"

    assert main([
        str(receiver_types), str(catalog), "--output", str(output),
        "--candidate-assessments-output", str(assessment_output),
    ]) == 0

    inference_row = json.loads(output.read_text(encoding="utf-8"))
    assessment_row = json.loads(assessment_output.read_text(encoding="utf-8"))
    assert inference_row["status"] == "resolved_unique_vtable"
    assert "candidate_assessment" not in inference_row
    assert assessment_row["status"] == "same_type_convergence"
