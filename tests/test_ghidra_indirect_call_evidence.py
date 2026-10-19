from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator

from revenginstr.indirect_call_slots import build_indirect_call_pointer_slots
from revenginstr.pointer_provenance import build_pointer_provenance

ROOT = Path(__file__).resolve().parents[1]


def test_indirect_call_evidence_contract() -> None:
    source = (ROOT / "ghidra/ExportGhidraIndirectCallEvidence.java").read_text(encoding="utf-8")
    for required in (
        '"REVENGINSTR.GhidraIndirectCallEvidence/4"',
        "getExecutableSHA256()",
        "architectureJson()",
        "resolveFunctionPointer",
        "parameterRootsJson",
        "resolved_static_function_pointer",
        "PcodeOp.CALLIND",
        "target_expression",
        "MAX_DEPTH = 6",
        "{depth-limit}",
        "{cycle}",
        "decompiler.decompileFunction(function, 60, monitor)",
        "op.getInput(0)",
    ):
        assert required in source
    for consumer_term in ("Nevergone", "NEVERGONE", "SHIFT", "EnemyObject", "HDVehicle"):
        assert consumer_term not in source

    schema = json.loads(
        (ROOT / "schemas/ghidra-indirect-call-evidence-v1.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate({
        "format": "REVENGINSTR.GhidraIndirectCallEvidence/1",
        "program": "sample",
        "requested": "00401000",
        "function_entry": "0x00401000",
        "call_address": "0x00401008",
        "call_time": 12,
        "target": "def:LOAD@00402000:5:8",
        "target_expression": "LOAD(register:RCX:8)",
        "arg_count": 2,
    })

    schema_v2 = json.loads(
        (ROOT / "schemas/ghidra-indirect-call-evidence-v2.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema_v2)
    Draft202012Validator(schema_v2).validate({
        "format": "REVENGINSTR.GhidraIndirectCallEvidence/2",
        "program": "sample",
        "program_sha256": "a" * 64,
        "architecture": {
            "language_id": "x86:LE:32:default", "pointer_width_bytes": 4, "endianness": "little",
        },
        "requested": "00401000",
        "function_entry": "0x00401000",
        "call_address": "0x00401008",
        "call_time": 12,
        "target": "def:LOAD@00402000:5:4",
        "target_expression": "LOAD(register:EAX:4)",
        "arg_count": 1,
    })

    schema_v3 = json.loads(
        (ROOT / "schemas/ghidra-indirect-call-evidence-v3.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema_v3)
    Draft202012Validator(schema_v3).validate({
        "format": "REVENGINSTR.GhidraIndirectCallEvidence/3",
        "program": "sample",
        "program_sha256": "a" * 64,
        "architecture": {
            "language_id": "x86:LE:32:default", "pointer_width_bytes": 4, "endianness": "little",
        },
        "requested": "00401000",
        "function_entry": "0x00401000",
        "call_address": "0x00401008",
        "call_time": 12,
        "target": "def:CAST@00401008:4:4",
        "target_expression": "CAST(address:00402000:4)",
        "target_resolution": {
            "status": "resolved_static_function_pointer",
            "slot_address": "0x00402000", "function_entry": "0x00401000",
        },
        "arg_count": 1,
    })

    schema_v4 = json.loads(
        (ROOT / "schemas/ghidra-indirect-call-evidence-v4.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema_v4)
    Draft202012Validator(schema_v4).validate({
        "format": "REVENGINSTR.GhidraIndirectCallEvidence/4",
        "program": "sample",
        "program_sha256": "a" * 64,
        "architecture": {
            "language_id": "x86:LE:32:default", "pointer_width_bytes": 4, "endianness": "little",
        },
        "requested": "00401000",
        "function_entry": "0x00401000",
        "call_address": "0x00401008",
        "call_time": 12,
        "target": "def:CAST@00401008:4:4",
        "target_expression": "CAST(address:00402000:4)",
        "target_resolution": {
            "status": "resolved_static_function_pointer",
            "slot_address": "0x00402000", "function_entry": "0x00401000",
        },
        "parameter_roots": [{
            "parameter_index": 0, "caller_parameter_index": 2, "argument_token": "register:EAX:4",
        }],
        "arg_count": 1,
    })


def test_indirect_call_runner_is_read_only_and_isolated() -> None:
    runner = (ROOT / "scripts/run_ghidra_indirect_call_evidence.sh").read_text(encoding="utf-8")
    assert "-readOnly" in runner
    assert "-noanalysis" in runner
    assert "mktemp -d" in runner
    assert "ExportGhidraIndirectCallEvidence.java" in runner


def test_real_ghidra_v4_replay_pins_callind_and_exact_parameter_root() -> None:
    fixture = ROOT / "tests/fixtures/ghidra-indirect-call-v4"
    binary = fixture / "callind.elf"
    call_rows = [json.loads(line) for line in (fixture / "callind.jsonl").read_text().splitlines()]
    acquisition_rows = [json.loads(line) for line in (fixture / "acquisition.jsonl").read_text().splitlines()]
    schema = json.loads((ROOT / "schemas/ghidra-indirect-call-evidence-v4.schema.json").read_text())
    validator = Draft202012Validator(schema)
    binary_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()

    assert len(call_rows) == 1
    for row in call_rows:
        validator.validate(row)
        assert row["program_sha256"] == binary_sha256
        assert row["architecture"] == {
            "language_id": "x86:LE:64:default", "pointer_width_bytes": 8, "endianness": "little",
        }
        assert row["target_resolution"] == {
            "status": "resolved_static_function_pointer",
            "slot_address": "0x00403000", "function_entry": "0x00401000",
        }
        assert row["parameter_roots"] == [{
            "parameter_index": 0,
            "caller_parameter_index": 0,
            "argument_token": "register:register:00000038:4",
        }]
    for row in acquisition_rows:
        assert row["state"] == "complete"
        if row["function_entry"] == "0040100f":
            assert row["callind_count"] == 1

    with (fixture / "flow.tsv").open(encoding="utf-8", newline="") as handle:
        flows = list(csv.DictReader(handle, delimiter="\t"))
    call = call_rows[0]
    site = next(row for row in flows if row["opcode"] == "CALLIND")
    assert int(site["op_address"], 16) == int(call["call_address"], 16)
    assert int(site["op_time"]) == call["call_time"]
    observed_count = 0 if site["inputs"] == "-" else len(site["inputs"].split(";"))
    assert observed_count == call["arg_count"]

    provenance = [
        json.loads(line) for line in (fixture / "pointer-provenance.jsonl").read_text().splitlines()
    ]
    slots = [json.loads(line) for line in (fixture / "pointer-slots.jsonl").read_text().splitlines()]
    provenance_schema = json.loads((ROOT / "schemas/pointer-provenance-v1.schema.json").read_text())
    slot_schema = json.loads((ROOT / "schemas/indirect-call-pointer-slot-v1.schema.json").read_text())
    for row in provenance:
        Draft202012Validator(provenance_schema).validate(row)
    for row in slots:
        Draft202012Validator(slot_schema).validate(row)
    assert slots[0]["source"]["indirect_call_evidence"]["artifact_sha256"] == hashlib.sha256(
        (fixture / "callind.jsonl").read_bytes()
    ).hexdigest()
    assert slots[0]["source"]["indirect_call_evidence"]["source_format"] == call["format"]
    assert slots[0]["status"] == "unsupported_target_operation"

    live_provenance = build_pointer_provenance(
        [fixture / "flow.tsv"], program_id="callind.elf",
        callind_evidence_paths=[fixture / "callind.jsonl"],
    )
    target_row = next(row for row in live_provenance if row["record_kind"] == "callind_target")
    assert target_row["target_source"]["source_format"] == call["format"]
    live_slots = build_indirect_call_pointer_slots(
        [fixture / "pointer-provenance.jsonl"], [fixture / "callind.jsonl"],
        program_id="callind.elf",
    )
    assert live_slots[0]["source"]["indirect_call_evidence"]["source_format"] == call["format"]
