from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


def test_generic_function_operand_contract() -> None:
    source = (ROOT / "ghidra/ExportGhidraFunctionOperands.java").read_text(encoding="utf-8")
    for required in (
        '"REVENGINSTR.GhidraFunctionOperand/1"',
        "scalar.bitLength()",
        "scalar.getSignedValue()",
        "scalar.getUnsignedValue()",
        "instruction.getOpObjects(operand)",
        "instruction.getReferencesFrom()",
        "reference.getReferenceType().isCall()",
    ):
        assert required in source
    for consumer_term in ("Nevergone", "SHIFT", "EnemyObject", "nearby_class_evidence"):
        assert consumer_term not in source

    schema = json.loads(
        (ROOT / "schemas/ghidra-function-operands-v1.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    common = {
        "format": "REVENGINSTR.GhidraFunctionOperand/1",
        "program": "sample",
        "requested": "00401000",
        "function_entry": "0x00401000",
        "instruction": "0x00401004",
        "operand": 1,
    }
    validator.validate({
        **common,
        "kind": "immediate",
        "bit_length": 32,
        "signed_value": "-1",
        "unsigned_hex": "0xffffffff",
        "target": None,
        "target_type": None,
        "number_value": None,
    })
    validator.validate({
        **common,
        "kind": "referenced-number",
        "bit_length": None,
        "signed_value": None,
        "unsigned_hex": None,
        "target": "0x00402000",
        "target_type": "dword",
        "number_value": "4294967295",
    })


def test_function_operand_runner_is_read_only_and_isolated() -> None:
    runner = (ROOT / "scripts/run_ghidra_function_operands.sh").read_text(encoding="utf-8")
    assert "-readOnly" in runner
    assert "-noanalysis" in runner
    assert "mktemp -d" in runner
    assert "ExportGhidraFunctionOperands.java" in runner
