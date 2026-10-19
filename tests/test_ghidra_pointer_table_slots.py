from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

ROOT = Path(__file__).resolve().parents[1]


def test_pointer_table_slot_schema_accepts_resolved_and_unmapped_rows() -> None:
    schema = json.loads((ROOT / "schemas/ghidra-pointer-table-slots-v1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    common = {
        "format": "REVENGINSTR.GhidraPointerTableSlots/1",
        "program_id": "sample.exe:analysis-1",
        "language_id": "x86:LE:32:default",
        "image_base": "0x400000",
        "pointer_size_bytes": 4,
        "table_index": 0,
        "table_address": "0x500000",
        "requested_slot_count": 2,
    }
    validator.validate({
        **common,
        "slot_index": 0,
        "slot_offset_bytes": 0,
        "slot_address": "0x500000",
        "raw_bytes": "00104000",
        "pointer_value": "0x401000",
        "target_address": "0x401000",
        "target_function": {"entry": "0x401000", "name": "FUN_00401000", "signature": "void FUN_00401000(void)"},
        "status": "function_entry",
    })
    validator.validate({
        **common,
        "slot_index": 1,
        "slot_offset_bytes": 4,
        "slot_address": "0x500004",
        "raw_bytes": "00000000",
        "pointer_value": "0x0",
        "target_address": None,
        "target_function": None,
        "status": "null_pointer",
    })
    with pytest.raises(ValidationError):
        validator.validate({
            **common,
            "slot_index": 2,
            "slot_offset_bytes": 8,
            "slot_address": "0x500008",
            "raw_bytes": "gggggggg",
            "pointer_value": "0x500000",
            "target_address": "0x500000",
            "target_function": None,
            "status": "mapped_non_function",
        })


def test_pointer_table_runner_is_bounded_read_only_and_uses_shared_exporter() -> None:
    runner = (ROOT / "scripts/run_ghidra_pointer_table_slots.sh").read_text()
    exporter = (ROOT / "ghidra/ExportGhidraPointerTableSlots.java").read_text()
    assert "-readOnly" in runner and "-noanalysis" in runner
    assert "ExportGhidraPointerTableSlots.java" in runner
    assert "TMP_SCRIPT_DIR" in runner and "POINTER_TABLE_SLOTS_FORMAT=REVENGINSTR.GhidraPointerTableSlots/1" in runner
    assert "MAX_SLOTS = 4096" in exporter and "MAX_TABLES = 64" in exporter
    assert "GhidraArm32ItaniumVtableSlots" not in exporter


def test_pointer_table_slot_schema_accepts_64_bit_pointer_rows() -> None:
    schema = json.loads((ROOT / "schemas/ghidra-pointer-table-slots-v1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate({
        "format": "REVENGINSTR.GhidraPointerTableSlots/1",
        "program_id": "sample64:analysis-1",
        "language_id": "x86:LE:64:default",
        "image_base": "0x140000000",
        "pointer_size_bytes": 8,
        "table_index": 0,
        "table_address": "0x140100000",
        "requested_slot_count": 1,
        "slot_index": 0,
        "slot_offset_bytes": 0,
        "slot_address": "0x140100000",
        "raw_bytes": "0010004001000000",
        "pointer_value": "0x140001000",
        "target_address": "0x140001000",
        "target_function": {"entry": "0x140001000", "name": "entry", "signature": "void entry(void)"},
        "status": "function_entry",
    })
