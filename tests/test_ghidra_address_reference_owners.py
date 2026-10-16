from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


def test_generic_address_reference_export_contract() -> None:
    source = (ROOT / "ghidra/ExportGhidraAddressReferenceOwners.java").read_text(encoding="utf-8")
    for required in (
        '"REVENGINSTR.GhidraAddressReferenceOwner/1"',
        "getReferencesTo(target)",
        "getFunctionContaining(from)",
        "getReferenceType()",
        "getOperandIndex()",
    ):
        assert required in source
    for consumer_term in ("Nevergone", "EnemyObject", "SHIFT", "nearby_class_evidence", "default_instance_"):
        assert consumer_term not in source

    schema = json.loads(
        (ROOT / "schemas/ghidra-address-reference-owners-v1.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate({
        "format": "REVENGINSTR.GhidraAddressReferenceOwner/1",
        "target_address": "00401000",
        "target_block": ".data",
        "target_symbol": "-",
        "reference_from": "00402010",
        "reference_type": "DATA",
        "reference_source": "ANALYSIS",
        "operand_index": "1",
        "from_symbol": "FUN_00402000",
        "from_instruction": "LOAD",
        "containing_function_entry": "00402000",
        "containing_function_name": "FUN_00402000",
    })


def test_address_reference_runner_is_read_only_and_isolated() -> None:
    runner = (ROOT / "scripts/run_ghidra_address_reference_owners.sh").read_text(encoding="utf-8")
    assert "-readOnly" in runner
    assert "-noanalysis" in runner
    assert "mktemp -d" in runner
    assert "ExportGhidraAddressReferenceOwners.java" in runner
