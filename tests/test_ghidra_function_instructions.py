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
    validator.validate({
        "format": "REVENGINSTR.GhidraFunctionInstructions/1",
        "program": "sample",
        "requested": "FUN_00401000",
        "resolved_address": "0x00401000",
        "found": True,
        "function": {
            "address": "0x00401000",
            "name": "sub_00401000",
            "size": 4,
            "calling_convention": "unknown",
        },
        "instruction_count": 1,
        "instructions": [{
            "address": "0x00401000",
            "bytes": "90",
            "mnemonic": "NOP",
            "text": "NOP",
            "operands": [],
            "flow_type": "FALL_THROUGH",
            "fallthrough": "0x00401001",
            "flows": [],
            "references": [],
            "pcode": [{
                "opcode": "COPY",
                "text": "unique[0x1:1] = COPY RAX",
                "output": {
                    "text": "unique[0x1:1]",
                    "space": "unique",
                    "offset": "0x1",
                    "size": 1,
                    "constant": False,
                    "register": False,
                    "unique": True,
                },
                "inputs": [],
            }],
        }],
    })
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
