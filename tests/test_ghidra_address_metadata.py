from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


def test_generic_address_metadata_contract() -> None:
    source = (ROOT / "ghidra/ExportGhidraAddressMetadata.java").read_text(encoding="utf-8")
    for required in (
        '"REVENGINSTR.GhidraAddressMetadata/1"',
        "getPrimarySymbol(address)",
        "getFunctionAt(address)",
        "getFunctionContaining(address)",
        "getInstructionAt(address)",
        "getDataAt(address)",
        "getBytes(address, bytes)",
    ):
        assert required in source
    for consumer_term in ("Nevergone", "SHIFT", "EnemyObject", "HDVehicle"):
        assert consumer_term not in source

    schema = json.loads(
        (ROOT / "schemas/ghidra-address-metadata-v1.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate({
        "format": "REVENGINSTR.GhidraAddressMetadata/1",
        "program": "sample",
        "requested": "00401000",
        "address": "0x00401000",
        "block": {
            "name": ".text",
            "start": "0x00401000",
            "end": "0x00401fff",
            "read": True,
            "write": False,
            "execute": True,
        },
        "primary_symbol": "sample_function",
        "function_at": {
            "entry": "0x00401000",
            "name": "sample_function",
            "body": "0x00401000..0x00401010",
            "is_thunk": False,
            "thunk_target": None,
        },
        "function_containing": {
            "entry": "0x00401000",
            "name": "sample_function",
            "body": "0x00401000..0x00401010",
        },
        "instruction_mnemonic": "MOV",
        "data_type": None,
        "raw_u32": "0x8b000000",
    })


def test_address_metadata_runner_is_read_only_and_isolated() -> None:
    runner = (ROOT / "scripts/run_ghidra_address_metadata.sh").read_text(encoding="utf-8")
    assert "-readOnly" in runner
    assert "-noanalysis" in runner
    assert "mktemp -d" in runner
    assert "ExportGhidraAddressMetadata.java" in runner
