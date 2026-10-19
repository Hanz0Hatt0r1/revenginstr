from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

ROOT = Path(__file__).resolve().parents[1]


def test_generic_parameter_store_export_contract() -> None:
    source = (ROOT / "ghidra/ExportGhidraParameterStoreField.java").read_text(encoding="utf-8")
    for required in (
        '"REVENGINSTR.GhidraParameterStoreField/1"',
        "PcodeOp.STORE",
        "PcodeOp.PTRSUB",
        "PcodeOp.PTRADD",
        "PcodeOp.INT_ADD",
        "parameterIndex(high, destination.base)",
        "parameterIndex(high, source)",
        "\"format\\tfunction_entry\\tfunction_name\\tstore_address\\tstore_time\\t\" +",
        "\"source_parameter_index\\tvalue_size\\tstatus\"",
    ):
        assert required in source
    for consumer_term in ("NEVERGONE", "Nevergone", "GameScene", "HDVehicle", "SHIFT"):
        assert consumer_term not in source

    schema = json.loads(
        (ROOT / "schemas/ghidra-parameter-store-field-v1.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    validator.validate({
        "format": "REVENGINSTR.GhidraParameterStoreField/1",
        "function_entry": "00401000",
        "function_name": "sub_00401000",
        "store_address": "00401020",
        "store_time": "7",
        "destination_parameter_index": "0",
        "destination_offset": "0x10",
        "destination_pattern": "ptrsub",
        "source_parameter_index": "1",
        "value_size": "4",
        "status": "parameter_to_parameter_field",
    })
    with pytest.raises(ValidationError):
        validator.validate({
            "format": "CONSUMER.ParameterStoreField/1",
            "function_entry": "00401000",
            "function_name": "sub_00401000",
            "store_address": "00401020",
            "store_time": "7",
            "destination_parameter_index": "-1",
            "destination_offset": "0x10",
            "destination_pattern": "ptrsub",
            "source_parameter_index": "1",
            "value_size": "4",
            "status": "parameter_to_parameter_field",
        })


def test_parameter_store_runner_is_read_only_and_isolated() -> None:
    runner = (ROOT / "scripts/run_ghidra_parameter_store_field.sh").read_text(encoding="utf-8")
    assert "-recursive" in runner
    assert "-readOnly" in runner
    assert "-noanalysis" in runner
    assert "mktemp -d" in runner
    assert "ExportGhidraParameterStoreField.java" in runner
    assert "--load-output" in runner
    assert "--function-entry" in runner
    assert '"${POST_SCRIPT_ARGS[@]}"' in runner


def test_parameter_store_exporter_supports_bounded_exact_entry_batches() -> None:
    source = (ROOT / "ghidra/ExportGhidraParameterStoreField.java").read_text(encoding="utf-8")
    assert "MAX_FUNCTIONS = 256" in source
    assert '"--function-entry".equals(option)' in source
    assert "getFunctionAt(address)" in source
    assert "functionEntries.add(entry)" in source
    assert "for (Function function : functions)" in source
    assert "GHIDRA_PARAMETER_STORE_FIELD_FUNCTIONS=" in source
