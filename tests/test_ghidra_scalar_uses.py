from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

ROOT = Path(__file__).resolve().parents[1]


def test_generic_scalar_use_export_contract() -> None:
    source = (ROOT / "ghidra/ExportGhidraScalarUses.java").read_text(encoding="utf-8")
    for required in (
        '"REVENGINSTR.GhidraScalarUses/1"',
        "instanceof Scalar",
        "Long.compareUnsigned",
        'mnemonic.equals("lea")',
        "Candidate inventory only",
        "scalar equality is never semantic identity",
    ):
        assert required in source
    for consumer_term in ("SHIFT", "Nevergone", "HDVehicle", "GameScene"):
        assert consumer_term not in source

    schema = json.loads(
        (ROOT / "schemas/ghidra-scalar-uses-v1.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    validator.validate({
        "format": "REVENGINSTR.GhidraScalarUses/1",
        "program": "sample.bin",
        "target_scalar": "0x2a",
        "function_address": "0x00401000",
        "function_name": "set_value",
        "instruction_address": "0x00401008",
        "mnemonic": "LEA",
        "text": "LEA EAX,[ESI + 0x2a]",
        "matching_operand_index": 1,
        "matching_operand_text": "[ESI + 0x2a]",
        "usage_class": "address-materializer",
    })
    with pytest.raises(ValidationError):
        validator.validate({
            "format": "SHIFT.GhidraScalarUses/1",
            "program": "sample.bin",
            "target_scalar": "0x2a",
            "function_address": None,
            "function_name": None,
            "instruction_address": "0x00401008",
            "mnemonic": "LEA",
            "text": "LEA EAX,[ESI + 0x2a]",
            "matching_operand_index": 1,
            "matching_operand_text": "[ESI + 0x2a]",
            "usage_class": "address-materializer",
        })


def test_scalar_use_runner_is_recursive_read_only_and_isolated() -> None:
    runner = (ROOT / "scripts/run_ghidra_scalar_uses.sh").read_text(encoding="utf-8")
    assert "-recursive" in runner
    assert "-readOnly" in runner
    assert "-noanalysis" in runner
    assert "mktemp -d" in runner
    assert "ExportGhidraScalarUses.java" in runner
