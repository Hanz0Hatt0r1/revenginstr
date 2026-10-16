from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


def schema(name: str) -> dict:
    value = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(value)
    return value


def test_generic_function_identity_export_contract() -> None:
    source = (ROOT / "ghidra/ExportGhidraFunctionIdentities.java").read_text(encoding="utf-8")
    for required in (
        '"REVENGINSTR.GhidraFunctionIdentity/1"',
        "plan_id\\trequested_entry\\tresolution",
        '"exact".equals(row.resolution)',
        '"containing".equals(row.resolution)',
    ):
        assert required in source
    for consumer_term in ("Nevergone", "EnemyObject", "SHIFT", "dispatch_slot_offset"):
        assert consumer_term not in source

    Draft202012Validator(schema("ghidra-function-identities-plan-v1.schema.json")).validate({
        "plan_id": "plan-0",
        "requested_entry": "00401000",
        "resolution": "exact",
    })
    Draft202012Validator(schema("ghidra-function-identities-v1.schema.json")).validate({
        "format": "REVENGINSTR.GhidraFunctionIdentity/1",
        "plan_id": "plan-0",
        "requested_entry": "00401000",
        "resolved_entry": "00401000",
        "short_name": "function",
        "qualified_name": "namespace::function",
        "signature": "void function(void)",
        "is_external": "false",
    })
