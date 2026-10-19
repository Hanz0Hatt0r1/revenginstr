from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

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
