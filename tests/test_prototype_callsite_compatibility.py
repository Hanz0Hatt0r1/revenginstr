from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.prototype_callsite_compatibility import check_callsite_compatibility

ROOT = Path(__file__).resolve().parents[1]
PROTOTYPES = ROOT / "tests/fixtures/ghidra-function-prototypes/prototypes.jsonl"
SCHEMA = json.loads(
    (ROOT / "schemas/function-prototype-callsite-compatibility-v1.schema.json").read_text()
)


def _observation(callee: str, count: int, index: int, *, program_id: str = "sample.exe") -> dict:
    return {
        "format": "REVENGINSTR.DirectCallArgumentObservation/1",
        "program_id": program_id,
        "program_sha256": "a" * 64,
        "caller_entry": f"004020{index:02x}",
        "callee_entry": callee,
        "call_address": f"004021{index:02x}",
        "call_time": index,
        "argument_count": count,
        "arguments": [
            {"index": arg, "value_token": f"input:Stack[0x{arg * 4 + 8:x}]:4", "width_bytes": 4}
            for arg in range(count)
        ],
        "evidence_ref": {
            "artifact_sha256": "b" * 64,
            "record_index": index,
            "source_format": "REVENGINSTR.GhidraFunctionPcodeFlow/1",
        },
    }


def _write_observations(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def test_fixed_and_missing_signatures_are_checked_with_both_source_refs(tmp_path: Path) -> None:
    Draft202012Validator.check_schema(SCHEMA)
    observations_path = tmp_path / "observations.jsonl"
    rows = [
        _observation("00401000", 2, 1),
        _observation("00401000", 1, 2),
        _observation("00409999", 0, 3),
    ]
    _write_observations(observations_path, rows)

    results = check_callsite_compatibility(observations_path, PROTOTYPES)
    validator = Draft202012Validator(SCHEMA)
    for result in results:
        validator.validate(result)

    assert [row["status"] for row in results] == ["compatible", "incompatible", "no_signature"]
    assert results[0]["expected_parameter_count"] == 2
    assert results[0]["signature_source"] == "USER_DEFINED"
    assert results[0]["prototype_evidence_ref"]["source_format"] == "REVENGINSTR.GhidraFunctionPrototype/1"
    assert results[0]["call_evidence_ref"]["source_format"] == "REVENGINSTR.DirectCallArgumentObservation/1"
    assert results[2]["prototype_evidence_ref"] is None


def test_variadic_signature_accepts_fixed_prefix_and_rejects_short_call(tmp_path: Path) -> None:
    record = json.loads(PROTOTYPES.read_text(encoding="utf-8").splitlines()[0])
    record["has_varargs"] = True
    prototypes_path = tmp_path / "variadic.jsonl"
    prototypes_path.write_text(json.dumps(record) + "\n", encoding="utf-8")
    observations_path = tmp_path / "observations.jsonl"
    _write_observations(observations_path, [
        _observation("00401000", 3, 1),
        _observation("00401000", 1, 2),
    ])

    results = check_callsite_compatibility(observations_path, prototypes_path)
    assert [row["status"] for row in results] == ["compatible", "incompatible"]


def test_mixed_program_ids_fail_closed(tmp_path: Path) -> None:
    observations_path = tmp_path / "observations.jsonl"
    _write_observations(observations_path, [_observation("00401000", 2, 1, program_id="other.exe")])

    with pytest.raises(ValueError, match="program_id differs"):
        check_callsite_compatibility(observations_path, PROTOTYPES)


def test_mixed_program_hashes_fail_closed(tmp_path: Path) -> None:
    observations_path = tmp_path / "observations.jsonl"
    row = _observation("00401000", 2, 1)
    row["program_sha256"] = "c" * 64
    _write_observations(observations_path, [row])

    with pytest.raises(ValueError, match="program_sha256 differs"):
        check_callsite_compatibility(observations_path, PROTOTYPES)
