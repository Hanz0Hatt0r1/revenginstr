from __future__ import annotations

import json
import hashlib
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.prototype_coverage import audit_prototype_coverage

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/ghidra-decompiler-parameters"
SCHEMA = json.loads(
    (ROOT / "schemas/function-prototype-evidence-coverage-v1.schema.json").read_text()
)


def _audit(observations: Path, acquisition: Path | None = None) -> dict:
    return audit_prototype_coverage(
        FIXTURES / "functions.tsv.gz",
        acquisition or FIXTURES / "acquisition.jsonl",
        FIXTURES / "decompiler-parameters.jsonl",
        observations,
        FIXTURES / "indirect-call-evidence.jsonl",
        [FIXTURES / "whole-program-flow.tsv"],
    )


def test_real_program_coverage_replay_matches_schema() -> None:
    Draft202012Validator.check_schema(SCHEMA)
    report = _audit(FIXTURES / "full-call-observations.jsonl")
    Draft202012Validator(SCHEMA).validate(report)
    assert report["function_population"] == {"total": 2, "internal": 2, "external": 0}
    assert report["pcode_flow"]["flow_rows"] == 12
    assert report["pcode_flow"]["complete_for_population"] is True
    assert report["decompiler_parameters"]["complete_for_population"] is True
    assert report["direct_calls"]["expected_resolved_sites"] == 1
    assert report["direct_calls"]["complete_for_flow_artifacts"] is True
    assert report["indirect_calls"]["expected_sites"] == 0
    assert report["full_program_coverage"] is True


def test_missing_call_observation_prevents_full_coverage(tmp_path: Path) -> None:
    observations = tmp_path / "empty.jsonl"
    observations.write_text("", encoding="utf-8")
    report = _audit(observations)
    Draft202012Validator(SCHEMA).validate(report)
    assert report["direct_calls"]["missing_sites"] == [{
        "caller_entry": "00010017", "call_address": "0001001f", "call_time": 14,
        "callee_entry": "00010000",
    }]
    assert report["full_program_coverage"] is False


def test_pcode_operation_count_mismatch_prevents_full_coverage(tmp_path: Path) -> None:
    rows = [
        json.loads(line)
        for line in (FIXTURES / "acquisition.jsonl").read_text().splitlines()
    ]
    rows[0]["operation_count"] += 1
    acquisition = tmp_path / "acquisition.jsonl"
    acquisition.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    report = _audit(FIXTURES / "full-call-observations.jsonl", acquisition)
    assert report["pcode_flow"]["operation_count_mismatches"] == [rows[0]["function_entry"]]
    assert report["pcode_flow"]["complete_for_population"] is False
    assert report["full_program_coverage"] is False


def test_call_observation_must_link_to_exact_source_flow_row(tmp_path: Path) -> None:
    row = json.loads((FIXTURES / "full-call-observations.jsonl").read_text().splitlines()[0])
    row["evidence_ref"]["record_index"] += 1
    observations = tmp_path / "wrong-source.jsonl"
    observations.write_text(json.dumps(row) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="exact P-code flow row"):
        _audit(observations)


def test_indirect_call_evidence_uses_batch_address_spelling(tmp_path: Path) -> None:
    flow = tmp_path / "flow.tsv"
    flow_text = (FIXTURES / "whole-program-flow.tsv").read_text(encoding="utf-8")
    flow_text += "00010017\t0001002b\t99\tCALLIND\tdef:0001002b:99:4\tinput:Stack[0x4]:4\t-\t-\n"
    flow.write_text(flow_text, encoding="utf-8")

    acquisition_rows = [
        json.loads(line) for line in (FIXTURES / "acquisition.jsonl").read_text().splitlines()
    ]
    acquisition_rows[1]["operation_count"] += 1
    acquisition_rows[1]["callind_count"] = 1
    acquisition = tmp_path / "acquisition.jsonl"
    acquisition.write_text("".join(json.dumps(row) + "\n" for row in acquisition_rows), encoding="utf-8")

    call_row = json.loads((FIXTURES / "full-call-observations.jsonl").read_text().splitlines()[0])
    call_row["evidence_ref"]["artifact_sha256"] = hashlib.sha256(flow.read_bytes()).hexdigest()
    observations = tmp_path / "calls.jsonl"
    observations.write_text(json.dumps(call_row) + "\n", encoding="utf-8")

    indirect = tmp_path / "indirect.jsonl"
    indirect.write_text(json.dumps({
        "format": "REVENGINSTR.GhidraIndirectCallEvidence/1",
        "program": "callsite_fixture.o",
        "requested": "00010017",
        "function_entry": "0x00010017",
        "call_address": "0x0001002b",
        "call_time": 99,
        "target": "input:Stack[0x4]:4",
        "target_expression": "input:Stack[0x4]:4",
        "arg_count": 1,
    }) + "\n", encoding="utf-8")

    report = audit_prototype_coverage(
        FIXTURES / "functions.tsv.gz", acquisition,
        FIXTURES / "decompiler-parameters.jsonl", observations, indirect, [flow],
    )
    Draft202012Validator(SCHEMA).validate(report)
    assert report["indirect_calls"]["expected_sites"] == 1
    assert report["indirect_calls"]["complete_for_flow_artifacts"] is True
    assert report["full_program_coverage"] is True


def test_v2_indirect_call_evidence_is_pinned_to_decompiler_program(tmp_path: Path) -> None:
    flow = tmp_path / "flow.tsv"
    flow.write_text(
        (FIXTURES / "whole-program-flow.tsv").read_text(encoding="utf-8")
        + "00010017\t0001002b\t99\tCALLIND\tdef:0001002b:99:4\tinput:Stack[0x4]:4\t-\t-\n",
        encoding="utf-8",
    )
    acquisition_rows = [
        json.loads(line) for line in (FIXTURES / "acquisition.jsonl").read_text().splitlines()
    ]
    acquisition_rows[1]["operation_count"] += 1
    acquisition_rows[1]["callind_count"] = 1
    acquisition = tmp_path / "acquisition.jsonl"
    acquisition.write_text("".join(json.dumps(row) + "\n" for row in acquisition_rows), encoding="utf-8")
    call_row = json.loads((FIXTURES / "full-call-observations.jsonl").read_text().splitlines()[0])
    call_row["evidence_ref"]["artifact_sha256"] = hashlib.sha256(flow.read_bytes()).hexdigest()
    observations = tmp_path / "calls.jsonl"
    observations.write_text(json.dumps(call_row) + "\n", encoding="utf-8")
    decompiler_row = json.loads((FIXTURES / "decompiler-parameters.jsonl").read_text().splitlines()[0])
    indirect_row = {
        "format": "REVENGINSTR.GhidraIndirectCallEvidence/2",
        "program": decompiler_row["program_id"],
        "program_sha256": decompiler_row["program_sha256"],
        "architecture": decompiler_row["architecture"],
        "requested": "00010017",
        "function_entry": "0x00010017",
        "call_address": "0x0001002b",
        "call_time": 99,
        "target": "input:Stack[0x4]:4",
        "target_expression": "input:Stack[0x4]:4",
        "arg_count": 1,
    }
    indirect = tmp_path / "indirect.jsonl"
    indirect.write_text(json.dumps(indirect_row) + "\n", encoding="utf-8")

    report = audit_prototype_coverage(
        FIXTURES / "functions.tsv.gz", acquisition,
        FIXTURES / "decompiler-parameters.jsonl", observations, indirect, [flow],
    )
    assert report["source_artifacts"]["indirect_call_evidence"]["source_format"] == indirect_row["format"]
    assert report["full_program_coverage"] is True

    indirect_row["program_sha256"] = "0" * 64
    indirect.write_text(json.dumps(indirect_row) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="does not match the expected binary"):
        audit_prototype_coverage(
            FIXTURES / "functions.tsv.gz", acquisition,
            FIXTURES / "decompiler-parameters.jsonl", observations, indirect, [flow],
        )
