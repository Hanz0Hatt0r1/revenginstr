from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

ROOT = Path(__file__).resolve().parents[1]


def test_generic_field_store_export_contract() -> None:
    source = (ROOT / "ghidra/ExportGhidraFieldStoreCandidates.java").read_text(encoding="utf-8")
    for required in (
        "public class ExportGhidraFieldStoreCandidates",
        "PcodeOp.STORE",
        "MAX_ADDRESS_DEPTH = 32",
        "functionNameMatches(function, functionNameFragments)",
        '"function_entry\\tfunction_name\\tstore_address\\tstore_time\\tfield_offset_hex\\taddress_opcode\\taddress_op_address\\taddress_op_time\\tbase_token\\tvalue_token\\tvalue_is_constant\\tvalue_constant_hex"',
    ):
        assert required in source
    for consumer_term in ("Nevergone", "GameScene", "HDVehicle", "SHIFT"):
        assert consumer_term not in source

    schema = json.loads(
        (ROOT / "schemas/ghidra-field-store-candidates-v1.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    validator.validate({
        "function_entry": "00401000",
        "function_name": "sub_00401000",
        "store_address": "00401020",
        "store_time": "7",
        "field_offset_hex": "0x24",
        "address_opcode": "PTRSUB",
        "address_op_address": "0040101c",
        "address_op_time": "4",
        "base_token": "register:r0:4",
        "value_token": "const:0x1:4",
        "value_is_constant": "1",
        "value_constant_hex": "0x1",
    })
    with pytest.raises(ValidationError):
        validator.validate({
            "function_entry": "00401000",
            "function_name": "sub_00401000",
            "store_address": "00401020",
            "store_time": "7",
            "field_offset_hex": "0x24",
            "address_opcode": "PTRSUB",
            "address_op_address": "0040101c",
            "address_op_time": "4",
            "base_token": "register:r0:4",
            "value_token": "def:00401018:2:4",
            "value_is_constant": "0",
            "value_constant_hex": "0x1",
        })
    with pytest.raises(ValidationError):
        validator.validate({
            "function_entry": "00401000",
            "function_name": "sub_00401000",
            "store_address": "00401020",
            "store_time": "seven",
            "field_offset_hex": "0x24",
            "address_opcode": "PTRSUB",
            "address_op_address": "0040101c",
            "address_op_time": "4",
            "base_token": "register:r0:4",
            "value_token": "const:0x1:4",
            "value_is_constant": "1",
            "value_constant_hex": "0x1",
        })


def test_field_store_runner_is_read_only_and_isolated() -> None:
    runner = (ROOT / "scripts/run_ghidra_field_store_candidates.sh").read_text(encoding="utf-8")
    assert "-readOnly" in runner
    assert "-noanalysis" in runner
    assert "mktemp -d" in runner
    assert "ExportGhidraFieldStoreCandidates.java" in runner
