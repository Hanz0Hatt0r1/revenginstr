from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


def test_caller_argument_subtree_contract_is_generic() -> None:
    source = (ROOT / "ghidra/ExportGhidraCallerArgumentSubtree.java").read_text(encoding="utf-8")
    for required in (
        '"REVENGINSTR.GhidraCallerArgumentSubtree/1"',
        '"REVENGINSTR.GhidraCallerArgumentParameterRoot/1"',
        '"REVENGINSTR.GhidraCallerArgumentParameterRoot/2"',
        "Expected plan_id, callee_entry, parameter_index header",
        "plan_id\\tcallee_entry\\tparameter_index",
        "parameterIndex(HighFunction high, Varnode node)",
        "--parameter-root-output",
        "--parameter-offset-root-output",
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


def test_caller_argument_parameter_root_sidecar_schema_and_runner() -> None:
    schema = json.loads(
        (ROOT / "schemas/ghidra-caller-argument-parameter-root-v1.schema.json").read_text()
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate({
        "format": "REVENGINSTR.GhidraCallerArgumentParameterRoot/1",
        "plan_id": "plan-0",
        "callee_entry": "00401000",
        "parameter_index": "1",
        "caller_entry": "00402000",
        "caller_call_site": "00402020",
        "caller_parameter_index": "0",
        "argument_node_id": "0",
        "status": "direct_parameter_root",
    })
    runner = (ROOT / "scripts/run_ghidra_caller_argument_subtree.sh").read_text(encoding="utf-8")
    assert "--parameter-root-output" in runner
    assert '"${POST_SCRIPT_ARGS[@]}"' in runner


def test_multiequal_root_offset_guard_is_preserved() -> None:
    source = (ROOT / "ghidra/ExportGhidraCallerArgumentSubtree.java").read_text(encoding="utf-8")
    assert (
        "else if (merged.parameterIndex != incoming.parameterIndex ||\n"
        "                            merged.offsetBytes != incoming.offsetBytes) return null;"
    ) in source
