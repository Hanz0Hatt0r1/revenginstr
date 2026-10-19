from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.prototype_callsite_observations import observe_call_arguments

ROOT = Path(__file__).resolve().parents[1]
FLOW_FIXTURE = ROOT / "tests/fixtures/ghidra-function-pcode-flow.tsv"
SCHEMA_PATH = ROOT / "schemas/direct-call-argument-observation-v1.schema.json"
FIELDS = [
    "function_entry", "op_address", "op_time", "opcode", "output", "inputs",
    "callee_entry", "callee_name",
]


def test_direct_call_observation_is_schema_valid_and_source_linked() -> None:
    rows = observe_call_arguments(
        [FLOW_FIXTURE], program_id="synthetic-x86", program_sha256="c" * 64,
    )
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(rows[0])

    assert len(rows) == 1
    assert rows[0]["caller_entry"] == "ram:00001000"
    assert rows[0]["callee_entry"] == "ram:00001020"
    assert rows[0]["program_id"] == "synthetic-x86"
    assert rows[0]["program_sha256"] == "c" * 64
    assert rows[0]["argument_count"] == 2
    assert [item["width_bytes"] for item in rows[0]["arguments"]] == [4, 4]
    assert rows[0]["evidence_ref"] == {
        "artifact_sha256": hashlib.sha256(FLOW_FIXTURE.read_bytes()).hexdigest(),
        "record_index": 1,
        "source_format": "REVENGINSTR.GhidraFunctionPcodeFlow/1",
    }


def test_zero_argument_calls_are_retained_and_unresolved_calls_are_skipped(tmp_path: Path) -> None:
    path = tmp_path / "flows.tsv"
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerow({
            "function_entry": "00401000", "op_address": "00401005", "op_time": "1",
            "opcode": "CALL", "output": "-", "inputs": "-", "callee_entry": "00402000",
            "callee_name": "target",
        })
        writer.writerow({
            "function_entry": "00401000", "op_address": "00401010", "op_time": "2",
            "opcode": "CALL", "output": "-", "inputs": "register:Stack[0x8]:8",
            "callee_entry": "-", "callee_name": "-",
        })
        writer.writerow({
            "function_entry": "00401000", "op_address": "00401020", "op_time": "3",
            "opcode": "CALLIND", "output": "-", "inputs": "-", "callee_entry": "-",
            "callee_name": "-",
        })

    rows = observe_call_arguments(
        [path], program_id="synthetic-x86", program_sha256="c" * 64,
    )
    assert len(rows) == 1
    assert rows[0]["argument_count"] == 0
    assert rows[0]["arguments"] == []


def test_duplicate_callsite_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "bad.tsv"
    row = {
        "function_entry": "00401000", "op_address": "00401005", "op_time": "1",
        "opcode": "CALL", "output": "-", "inputs": "input:Stack[0x8]:4",
        "callee_entry": "00402000", "callee_name": "target",
    }
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerow(row)
        writer.writerow(row)

    with pytest.raises(ValueError, match="duplicate direct call site"):
        observe_call_arguments([path], program_id="synthetic-x86", program_sha256="c" * 64)


def test_bad_argument_width_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "bad-width.tsv"
    row = {
        "function_entry": "00401000", "op_address": "00401005", "op_time": "1",
        "opcode": "CALL", "output": "-", "inputs": "input:Stack[0x8]",
        "callee_entry": "00402000", "callee_name": "target",
    }
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerow(row)

    with pytest.raises(ValueError, match="no positive byte width"):
        observe_call_arguments([path], program_id="synthetic-x86", program_sha256="c" * 64)


def test_program_sha256_must_be_lowercase_sha256() -> None:
    with pytest.raises(ValueError, match="program_sha256 must be lowercase SHA-256"):
        observe_call_arguments([FLOW_FIXTURE], program_id="synthetic-x86", program_sha256="C" * 64)
