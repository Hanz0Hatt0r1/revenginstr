from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]


def test_language_address_space_export_contract() -> None:
    source = (ROOT / "ghidra/ExportGhidraLanguageAddressSpaces.java").read_text(encoding="utf-8")
    assert '"REVENGINSTR.GhidraLanguageAddressSpaces/1"' in source
    assert "getAllAddressSpaces()" in source
    assert "getSpaceID()" in source
    assert "getAddressableUnitSize()" in source
    assert "isBigEndian()" in source
    for consumer_term in ("Nevergone", "SHIFT", "HDVehicle", "EnemyObject"):
        assert consumer_term not in source

    schema = json.loads((ROOT / "schemas/ghidra-language-address-spaces-v1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate({
        "format": "REVENGINSTR.GhidraLanguageAddressSpaces/1",
        "language_id": "x86:LE:32:default",
        "big_endian": False,
        "default_space": "ram",
        "default_data_space": "ram",
        "address_spaces": [{
            "space_id": "0x1a1",
            "name": "ram",
            "pointer_size": 4,
            "addressable_unit_size": 1,
            "memory": True,
            "loaded_memory": True,
            "constant": False,
            "register": False,
            "stack": False,
            "unique": False,
            "external": False,
            "overlay": False,
        }],
    })


def test_language_address_space_runner_is_read_only_and_validates_ids() -> None:
    runner = (ROOT / "scripts/run_ghidra_language_address_spaces.sh").read_text(encoding="utf-8")
    assert "-readOnly" in runner
    assert "-noanalysis" in runner
    assert "mktemp -d" in runner
    assert "ExportGhidraLanguageAddressSpaces.java" in runner
    assert "duplicate Ghidra language address-space id or name" in runner
