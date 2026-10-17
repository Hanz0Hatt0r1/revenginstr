from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


def test_generic_function_instruction_contract() -> None:
    source = (ROOT / "ghidra/ExportGhidraFunctionInstructions.java").read_text(encoding="utf-8")
    for required in (
        '"REVENGINSTR.GhidraFunctionInstructions/1"',
        "listing.getInstructions(function.getBody(), true)",
        "instruction.getPcode()",
        "instruction.getReferencesFrom()",
        "instruction.getFlows()",
        "node.isConstant()",
        "node.isRegister()",
    ):
        assert required in source
    for consumer_term in ("Nevergone", "SHIFT", "EnemyObject", "nearby_class_evidence"):
        assert consumer_term not in source

    schema = json.loads(
        (ROOT / "schemas/ghidra-function-instructions-v1.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    fixture = json.loads(
        (ROOT / "tests/fixtures/ghidra-instructions/function-instructions.json").read_text(encoding="utf-8")
    )
    validator.validate(fixture)
    validator.validate({
        "format": "REVENGINSTR.GhidraFunctionInstructions/1",
        "program": "sample",
        "requested": "00402000",
        "resolved_address": "0x00402000",
        "found": False,
        "function": None,
        "instruction_count": 0,
        "instructions": [],
    })


def test_function_instruction_runner_is_read_only_and_isolated() -> None:
    runner = (ROOT / "scripts/run_ghidra_function_instructions.sh").read_text(encoding="utf-8")
    assert "-readOnly" in runner
    assert "-noanalysis" in runner
    assert "mktemp -d" in runner
    assert "ExportGhidraFunctionInstructions.java" in runner
