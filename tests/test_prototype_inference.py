from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.prototype_callsite_observations import observe_call_arguments
from revenginstr.prototype_inference import infer_prototypes

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/ghidra-decompiler-parameters"
HYPOTHESIS_SCHEMA = json.loads((ROOT / "schemas/function-prototype-hypothesis-v1.schema.json").read_text())


def test_prototype_inference_joins_formals_and_call_arity_as_review_evidence() -> None:
    rows = infer_prototypes(
        FIXTURES / "decompiler-parameters.jsonl", FIXTURES / "call-observations.jsonl",
    )
    for row in rows:
        Draft202012Validator(HYPOTHESIS_SCHEMA).validate(row)
    add = next(row for row in rows if row["function_entry"] == "00010000")
    candidate = add["candidates"][0]
    assert add["status"] == "review"
    assert candidate["parameter_count"] == 2
    assert [param["kind"] for param in candidate["parameters"]] == ["pointer", "scalar"]
    assert candidate["return_value"] == {"kind": "pointer", "width_bytes": 4}
    assert candidate["confidence"] < 0.95
    assert [ref["source_format"] for ref in candidate["evidence_refs"]] == [
        "REVENGINSTR.GhidraDecompilerParameters/1",
        "REVENGINSTR.DirectCallArgumentObservation/1",
    ]


def test_exact_call_result_return_path_adds_only_a_review_candidate(tmp_path: Path) -> None:
    functions = [
        json.loads(line)
        for line in (FIXTURES / "decompiler-parameters.jsonl").read_text().splitlines()
    ]
    caller = next(row for row in functions if row["function_entry"] == "00010017")
    caller["signature_source"] = "DEFAULT"
    caller["return_type"] = {
        "kind": "unknown", "name": "undefined4", "path": "/undefined4", "width_bytes": 4,
    }
    decompiler = tmp_path / "decompiler.jsonl"
    decompiler.write_text("".join(json.dumps(row) + "\n" for row in functions), encoding="utf-8")

    flow = tmp_path / "forward-return.tsv"
    flow.write_text(
        "function_entry\top_address\top_time\topcode\toutput\tinputs\tcallee_entry\tcallee_name\n"
        "00010017\t0001001f\t14\tCALL\tdef:0001001f:14:4\tinput:Stack[0x4]:4;const:0x3:4\t00010000\tsample_add\n"
        "00010017\t00010020\t15\tCOPY\tdef:00010020:15:4\tdef:0001001f:14:4\t-\t-\n"
        "00010017\t00010024\t20\tRETURN\t-\tconst:0x0:4;def:00010020:15:4\t-\t-\n",
        encoding="utf-8",
    )
    metadata = functions[0]
    observations = observe_call_arguments(
        [flow], program_id=metadata["program_id"], program_sha256=metadata["program_sha256"],
    )
    calls = tmp_path / "calls.jsonl"
    calls.write_text("".join(json.dumps(row) + "\n" for row in observations), encoding="utf-8")

    rows = infer_prototypes(decompiler, calls, function_pcode_flow_paths=[flow])
    caller_hypothesis = next(row for row in rows if row["function_entry"] == "00010017")
    Draft202012Validator(HYPOTHESIS_SCHEMA).validate(caller_hypothesis)
    assert caller_hypothesis["status"] == "review"
    assert caller_hypothesis["candidates"][0]["return_value"] == {"kind": "unknown", "width_bytes": 4}
    suggestion = next(row for row in caller_hypothesis["candidates"] if row["candidate_id"] == "direct-call-return-shape")
    assert suggestion["return_value"] == {"kind": "pointer", "width_bytes": 4}
    assert suggestion["confidence"] == 0.35
    assert any(ref["source_format"] == "REVENGINSTR.GhidraFunctionPcodeFlow/1" for ref in suggestion["evidence_refs"])

    flow_text = flow.read_text(encoding="utf-8")
    reversed_return = flow_text.replace(
        "const:0x0:4;def:00010020:15:4", "def:00010020:15:4;const:0x0:4",
    )
    assert reversed_return != flow_text
    flow.write_text(reversed_return, encoding="utf-8")
    observations = observe_call_arguments(
        [flow], program_id=metadata["program_id"], program_sha256=metadata["program_sha256"],
    )
    calls.write_text("".join(json.dumps(row) + "\n" for row in observations), encoding="utf-8")
    rows = infer_prototypes(decompiler, calls, function_pcode_flow_paths=[flow])
    caller_hypothesis = next(row for row in rows if row["function_entry"] == "00010017")
    assert len(caller_hypothesis["candidates"]) == 1


def test_call_result_that_is_cast_and_loaded_does_not_propagate_return_shape() -> None:
    fixture = ROOT / "tests/fixtures/ghidra-untyped-prototype"
    rows = infer_prototypes(
        fixture / "decompiler-parameters.jsonl", fixture / "call-observations.jsonl",
        caller_parameter_roots_path=fixture / "prototype-parameter-roots.tsv",
        function_pcode_flow_paths=[fixture / "whole-program-flow.tsv"],
    )
    expected = [json.loads(line) for line in (fixture / "hypotheses.jsonl").read_text().splitlines()]
    assert rows == expected
    caller = next(row for row in rows if row["function_entry"] == "00010017")
    assert all(candidate["candidate_id"] != "direct-call-return-shape" for candidate in caller["candidates"])
    assert caller["candidates"][0]["return_value"] == {"kind": "unknown", "width_bytes": 4}


def test_real_ghidra_tail_call_replay_emits_a_low_confidence_alternative() -> None:
    fixture = ROOT / "tests/fixtures/ghidra-tail-call-return"
    rows = infer_prototypes(
        fixture / "decompiler-parameters.jsonl", fixture / "call-observations.jsonl",
        function_pcode_flow_paths=[fixture / "forward-flow.tsv"],
    )
    expected = [json.loads(line) for line in (fixture / "hypotheses.jsonl").read_text().splitlines()]
    assert rows == expected
    caller = next(row for row in rows if row["function_entry"] == "00010017")
    Draft202012Validator(HYPOTHESIS_SCHEMA).validate(caller)
    assert caller["candidates"][0]["return_value"] == {"kind": "void", "width_bytes": None}
    suggestion = caller["candidates"][1]
    assert suggestion["candidate_id"] == "possible-tail-call-return"
    assert suggestion["return_value"] == {"kind": "pointer", "width_bytes": 4}
    assert suggestion["confidence"] == 0.2
    assert len([ref for ref in suggestion["evidence_refs"] if ref["source_format"] == "REVENGINSTR.GhidraFunctionPcodeFlow/1"]) == 2


def test_return_shape_inference_does_not_override_user_defined_void(tmp_path: Path) -> None:
    fixture = ROOT / "tests/fixtures/ghidra-tail-call-return"
    functions = [
        json.loads(line)
        for line in (fixture / "decompiler-parameters.jsonl").read_text().splitlines()
    ]
    functions[1]["signature_source"] = "USER_DEFINED"
    decompiler = tmp_path / "decompiler.jsonl"
    decompiler.write_text("".join(json.dumps(row) + "\n" for row in functions), encoding="utf-8")
    rows = infer_prototypes(
        decompiler, fixture / "call-observations.jsonl",
        function_pcode_flow_paths=[fixture / "forward-flow.tsv"],
    )
    caller = next(row for row in rows if row["function_entry"] == "00010017")
    assert len(caller["candidates"]) == 1
    assert caller["candidates"][0]["return_value"] == {"kind": "void", "width_bytes": None}


def test_call_arity_conflict_is_preserved_instead_of_unified(tmp_path: Path) -> None:
    row = json.loads((FIXTURES / "call-observations.jsonl").read_text().splitlines()[0])
    row["arguments"].append({"index": 2, "value_token": "const:0x4:4", "width_bytes": 4})
    row["argument_count"] = 3
    calls = tmp_path / "calls.jsonl"
    calls.write_text(json.dumps(row) + "\n", encoding="utf-8")
    inferred = infer_prototypes(FIXTURES / "decompiler-parameters.jsonl", calls)
    add = next(item for item in inferred if item["function_entry"] == "00010000")
    Draft202012Validator(HYPOTHESIS_SCHEMA).validate(add)
    assert add["status"] == "conflicted"
    assert [conflict["reason"] for conflict in add["conflicts"]] == [
        "incompatible_parameter_counts",
    ]
    assert len(add["conflicts"][0]["evidence_refs"]) == 2


def test_resolved_indirect_target_constrains_prototype_arity(tmp_path: Path) -> None:
    decompiler_path = FIXTURES / "decompiler-parameters.jsonl"
    decompiler = json.loads(decompiler_path.read_text().splitlines()[0])
    evidence = {
        "format": "REVENGINSTR.GhidraIndirectCallEvidence/3",
        "program": decompiler["program_id"],
        "program_sha256": decompiler["program_sha256"],
        "architecture": decompiler["architecture"],
        "requested": "00010017",
        "function_entry": "0x00010017",
        "call_address": "0x0001002b",
        "call_time": 99,
        "target": "def:CAST@0001002b:22:4",
        "target_expression": "CAST(address:00011000:4)",
        "target_resolution": {
            "status": "resolved_static_function_pointer",
            "slot_address": "0x00011000", "function_entry": "0x00010000",
        },
        "arg_count": 1,
    }
    evidence_path = tmp_path / "indirect.jsonl"
    evidence_path.write_text(json.dumps(evidence) + "\n", encoding="utf-8")

    rows = infer_prototypes(
        decompiler_path, FIXTURES / "call-observations.jsonl",
        indirect_call_evidence_path=evidence_path,
    )
    target = next(row for row in rows if row["function_entry"] == "00010000")
    Draft202012Validator(HYPOTHESIS_SCHEMA).validate(target)
    assert target["status"] == "conflicted"
    conflict = next(row for row in target["conflicts"] if row["reason"] == "incompatible_parameter_counts")
    assert any(ref["source_format"] == evidence["format"] for ref in conflict["evidence_refs"])


def test_unresolved_indirect_target_does_not_constrain_prototype(tmp_path: Path) -> None:
    decompiler_path = FIXTURES / "decompiler-parameters.jsonl"
    decompiler = json.loads(decompiler_path.read_text().splitlines()[0])
    evidence = {
        "format": "REVENGINSTR.GhidraIndirectCallEvidence/3",
        "program": decompiler["program_id"],
        "program_sha256": decompiler["program_sha256"],
        "architecture": decompiler["architecture"],
        "requested": "00010017",
        "function_entry": "0x00010017",
        "call_address": "0x0001002b",
        "call_time": 99,
        "target": "register:EBX:4",
        "target_expression": "register:EBX:4",
        "target_resolution": {
            "status": "unsupported_target_expression", "slot_address": None, "function_entry": None,
        },
        "arg_count": 99,
    }
    evidence_path = tmp_path / "indirect.jsonl"
    evidence_path.write_text(json.dumps(evidence) + "\n", encoding="utf-8")
    rows = infer_prototypes(
        decompiler_path, FIXTURES / "call-observations.jsonl",
        indirect_call_evidence_path=evidence_path,
    )
    target = next(row for row in rows if row["function_entry"] == "00010000")
    assert target["status"] == "review"
    assert all(conflict["reason"] != "incompatible_parameter_counts" for conflict in target["conflicts"])


def test_real_ghidra_static_target_constrains_the_matching_prototype(tmp_path: Path) -> None:
    fixture = ROOT / "tests/fixtures/ghidra-indirect-call-v4"
    direct_calls = tmp_path / "direct-calls.jsonl"
    direct_calls.write_text("", encoding="utf-8")
    rows = infer_prototypes(
        fixture / "decompiler-parameters.jsonl", direct_calls,
        indirect_call_evidence_path=fixture / "callind.jsonl",
    )
    target = next(row for row in rows if row["function_entry"] == "00401000")
    Draft202012Validator(HYPOTHESIS_SCHEMA).validate(target)
    assert target["candidates"][0]["parameter_count"] == 1
    assert target["status"] == "review"
    assert target["conflicts"] == []
    assert any(
        ref["source_format"] == "REVENGINSTR.GhidraIndirectCallEvidence/4"
        for ref in target["candidates"][0]["evidence_refs"]
    )


def test_v4_indirect_exact_parameter_root_propagates_shape(tmp_path: Path) -> None:
    fixture = ROOT / "tests/fixtures/ghidra-untyped-prototype"
    decompiler_path = fixture / "decompiler-parameters.jsonl"
    decompiler = json.loads(decompiler_path.read_text().splitlines()[0])
    evidence = {
        "format": "REVENGINSTR.GhidraIndirectCallEvidence/4",
        "program": decompiler["program_id"],
        "program_sha256": decompiler["program_sha256"],
        "architecture": decompiler["architecture"],
        "requested": "00010017",
        "function_entry": "0x00010017",
        "call_address": "0x0001002b",
        "call_time": 99,
        "target": "def:CAST@0001002b:22:4",
        "target_expression": "CAST(address:00011000:4)",
        "target_resolution": {
            "status": "resolved_static_function_pointer",
            "slot_address": "0x00011000", "function_entry": "0x00010000",
        },
        "parameter_roots": [{
            "parameter_index": 0, "caller_parameter_index": 0,
            "argument_token": "register:EBX:4",
        }],
        "arg_count": 2,
    }
    evidence_path = tmp_path / "indirect-v4.jsonl"
    evidence_path.write_text(json.dumps(evidence) + "\n", encoding="utf-8")
    direct_calls = tmp_path / "empty-direct-calls.jsonl"
    direct_calls.write_text("", encoding="utf-8")

    rows = infer_prototypes(
        decompiler_path, direct_calls, indirect_call_evidence_path=evidence_path,
    )
    caller = next(row for row in rows if row["function_entry"] == "00010017")
    Draft202012Validator(HYPOTHESIS_SCHEMA).validate(caller)
    assert caller["candidates"][0]["parameters"][0]["kind"] == "pointer"
    assert any(
        ref["source_format"] == evidence["format"]
        for ref in caller["candidates"][0]["parameters"][0]["evidence_refs"]
    )


def test_real_ghidra_indirect_parameter_root_changes_unknown_formal_to_scalar() -> None:
    fixture = ROOT / "tests/fixtures/ghidra-indirect-call-v4"
    rows = infer_prototypes(
        fixture / "decompiler-parameters.jsonl",
        fixture / "direct-call-observations.jsonl",
        indirect_call_evidence_path=fixture / "callind.jsonl",
    )
    expected = [json.loads(line) for line in (fixture / "hypotheses.jsonl").read_text().splitlines()]
    assert rows == expected
    caller = next(row for row in rows if row["function_entry"] == "0040100f")
    Draft202012Validator(HYPOTHESIS_SCHEMA).validate(caller)
    assert caller["candidates"][0]["parameters"][0]["kind"] == "scalar"
    assert any(
        ref["source_format"] == "REVENGINSTR.GhidraIndirectCallEvidence/4"
        for ref in caller["candidates"][0]["parameters"][0]["evidence_refs"]
    )


def test_variadic_call_keeps_fixed_prefix_without_claiming_total_arity(tmp_path: Path) -> None:
    functions = [
        json.loads(line)
        for line in (FIXTURES / "decompiler-parameters.jsonl").read_text().splitlines()
    ]
    functions[0]["has_varargs"] = True
    decompiler = tmp_path / "decompiler.jsonl"
    decompiler.write_text("".join(json.dumps(row) + "\n" for row in functions), encoding="utf-8")
    call = json.loads((FIXTURES / "call-observations.jsonl").read_text().splitlines()[0])
    call["arguments"].append({"index": 2, "value_token": "const:0x4:4", "width_bytes": 4})
    call["argument_count"] = 3
    calls = tmp_path / "calls.jsonl"
    calls.write_text(json.dumps(call) + "\n", encoding="utf-8")

    add = next(
        row for row in infer_prototypes(decompiler, calls)
        if row["function_entry"] == "00010000"
    )
    Draft202012Validator(HYPOTHESIS_SCHEMA).validate(add)
    assert add["status"] == "review"
    assert add["conflicts"] == []
    assert add["candidates"][0]["parameter_count"] is None
    assert len(add["candidates"][0]["parameters"]) == 2


def test_failed_decompilation_yields_unknown_review_candidate(tmp_path: Path) -> None:
    functions = [
        json.loads(line)
        for line in (FIXTURES / "decompiler-parameters.jsonl").read_text().splitlines()
    ]
    functions[0].update({
        "status": "decompile_failed", "parameter_count": None,
        "parameters": [], "return_type": None, "error": "timeout",
    })
    decompiler = tmp_path / "decompiler.jsonl"
    decompiler.write_text("".join(json.dumps(row) + "\n" for row in functions), encoding="utf-8")
    rows = infer_prototypes(decompiler, FIXTURES / "call-observations.jsonl")
    add = next(row for row in rows if row["function_entry"] == "00010000")
    Draft202012Validator(HYPOTHESIS_SCHEMA).validate(add)
    assert add["status"] == "review"
    assert add["candidates"][0]["parameter_count"] is None
    assert add["candidates"][0]["parameters"] == []
    assert add["candidates"][0]["return_value"] == {"kind": "unknown", "width_bytes": None}


def test_inference_rejects_program_hash_mismatch_and_unplanned_callee(tmp_path: Path) -> None:
    row = json.loads((FIXTURES / "call-observations.jsonl").read_text().splitlines()[0])
    row["program_sha256"] = "f" * 64
    mismatch = tmp_path / "mismatch.jsonl"
    mismatch.write_text(json.dumps(row) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="do not match"):
        infer_prototypes(FIXTURES / "decompiler-parameters.jsonl", mismatch)

    row["program_sha256"] = "088daee59450d63d8428b33f7e3654898cd7fc40ef8ca140211fe618a3f4ff9a"
    row["callee_entry"] = "0001ffff"
    missing = tmp_path / "missing.jsonl"
    missing.write_text(json.dumps(row) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="omits 1 observed callees"):
        infer_prototypes(FIXTURES / "decompiler-parameters.jsonl", missing)
