from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


def test_generic_address_reference_export_contract() -> None:
    source = (ROOT / "ghidra/ExportGhidraAddressReferences.java").read_text(encoding="utf-8")
    for required in (
        '"REVENGINSTR.GhidraAddressReferences/1"',
        "references.getReferencesTo(address)",
        "ref.getReferenceType().getName()",
        "ref.getSource().toString()",
        "ref.isPrimary()",
        "listing.getInstructionAt(from)",
        "getExecutableMD5()",
    ):
        assert required in source
    for consumer_term in ("Nevergone", "SHIFT", "EnemyObject", "nearby_class_evidence"):
        assert consumer_term not in source

    schema = json.loads(
        (ROOT / "schemas/ghidra-address-references-v1.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    validator.validate({
        "format": "REVENGINSTR.GhidraAddressReferences/1",
        "program": "sample",
        "executable_md5": "0123456789abcdef0123456789abcdef",
        "requested": "DAT_00401000",
        "resolved_address": "0x00401000",
        "found": True,
        "target_block": ".data",
        "primary_symbol": "sample_value",
        "data_type": "int",
        "data_length": 4,
        "reference_count": 1,
        "function_addresses": ["0x00402000"],
        "references": [{
            "from": "0x00402004",
            "type": "DATA",
            "source": "ANALYSIS",
            "operand_index": 1,
            "primary": True,
            "function_address": "0x00402000",
            "function_name": "sample_reader",
            "instruction": "MOV EAX,[0x00401000]",
        }],
    })
    validator.validate({
        "format": "REVENGINSTR.GhidraAddressReferences/1",
        "program": "sample",
        "executable_md5": None,
        "requested": "invalid",
        "resolved_address": None,
        "found": False,
        "target_block": None,
        "primary_symbol": None,
        "data_type": None,
        "data_length": 0,
        "reference_count": 0,
        "function_addresses": [],
        "references": [],
    })


def test_address_reference_runner_is_read_only_and_isolated() -> None:
    runner = (ROOT / "scripts/run_ghidra_address_references.sh").read_text(encoding="utf-8")
    assert "-readOnly" in runner
    assert "-noanalysis" in runner
    assert "mktemp -d" in runner
    assert "ExportGhidraAddressReferences.java" in runner
