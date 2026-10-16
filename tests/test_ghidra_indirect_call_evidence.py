from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


def test_indirect_call_evidence_contract() -> None:
    source = (ROOT / "ghidra/ExportGhidraIndirectCallEvidence.java").read_text(encoding="utf-8")
    for required in (
        '"REVENGINSTR.GhidraIndirectCallEvidence/1"',
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


def test_indirect_call_runner_is_read_only_and_isolated() -> None:
    runner = (ROOT / "scripts/run_ghidra_indirect_call_evidence.sh").read_text(encoding="utf-8")
    assert "-readOnly" in runner
    assert "-noanalysis" in runner
    assert "mktemp -d" in runner
    assert "ExportGhidraIndirectCallEvidence.java" in runner
