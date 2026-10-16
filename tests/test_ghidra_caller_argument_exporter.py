from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


def test_caller_argument_subtree_contract_is_generic() -> None:
    source = (ROOT / "ghidra/ExportGhidraCallerArgumentSubtree.java").read_text(encoding="utf-8")
    for required in (
        '"REVENGINSTR.GhidraCallerArgumentSubtree/1"',
        "Expected plan_id, callee_entry, parameter_index header",
        "plan_id\\tcallee_entry\\tparameter_index",
        "MAX_DEPTH = 12",
        "MAX_NODES = 96",
        "MAX_CALLERS = 128",
    ):
        assert required in source
    for consumer_term in ("Nevergone", "EnemyObject", "EnemyActionsSystem", "dispatch_slot_offset"):
        assert consumer_term not in source

    plan_schema = json.loads((ROOT / "schemas/ghidra-caller-argument-subtree-plan-v1.schema.json").read_text())
    Draft202012Validator.check_schema(plan_schema)
    Draft202012Validator(plan_schema).validate({
        "plan_id": "plan-0",
        "callee_entry": "00401000",
        "parameter_index": "0",
    })

    schema = json.loads((ROOT / "schemas/ghidra-caller-argument-subtree-v1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate({
        "format": "REVENGINSTR.GhidraCallerArgumentSubtree/1",
        "row_type": "summary",
        "plan_id": "plan-0",
        "callee_entry": "00401000",
        "parameter_index": "0",
        "direct_caller_functions": "2",
        "caller_functions_decompiled": "2",
        "caller_functions_failed": "0",
        "callers_with_matched_calls": "2",
        "matched_caller_calls": "3",
        "caller_entry": "-",
        "caller_name": "-",
        "caller_call_site": "-",
        "node_id": "-",
        "parent_node_id": "-",
        "input_index": "-",
        "depth": "-",
        "edge_kind": "-",
        "node_token": "-",
        "type_display": "-",
        "pointer_depth": "-",
        "pointee_type_display": "-",
        "constant_value": "-",
        "defining_opcode": "-",
        "defining_address": "-",
        "defining_time": "-",
        "call_target_entry": "-",
        "call_target_name": "-",
        "truncation": "-",
        "status": "complete_caller_argument_subtrees",
    })
