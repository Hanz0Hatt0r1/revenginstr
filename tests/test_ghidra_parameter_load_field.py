from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]


def test_parameter_load_export_uses_formal_parameter_address_roots() -> None:
    source = (ROOT / "ghidra/ExportGhidraParameterStoreField.java").read_text(encoding="utf-8")
    for required in (
        '"REVENGINSTR.GhidraParameterLoadField/1"',
        "op.getOpcode() == PcodeOp.LOAD",
        "decodeAddress(op.getInput(1))",
        "parameterIndex(high, address.base)",
        '"base_parameter_index\\tfield_offset\\taddress_pattern\\tvalue_size\\tvalue_token\\tstatus"',
    ):
        assert required in source
    for consumer_term in ("NEVERGONE", "Nevergone", "GameScene", "HDVehicle", "SHIFT"):
        assert consumer_term not in source


def test_parameter_load_schema_accepts_synthetic_row() -> None:
    schema = json.loads(
        (ROOT / "schemas/ghidra-parameter-load-field-v1.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate({
        "format": "REVENGINSTR.GhidraParameterLoadField/1",
        "function_entry": "00401000",
        "function_name": "sub_00401000",
        "load_address": "00401020",
        "load_time": "8",
        "base_parameter_index": "0",
        "field_offset": "0x10",
        "address_pattern": "ptrsub",
        "value_size": "4",
        "value_token": "def:LOAD@00401020:8:4",
        "status": "parameter_field_load",
    })


def test_parameter_load_runner_keeps_store_output_optional_contract() -> None:
    runner = (ROOT / "scripts/run_ghidra_parameter_store_field.sh").read_text(encoding="utf-8")
    assert "-readOnly" in runner
    assert "-noanalysis" in runner
    assert "--load-output" in runner
