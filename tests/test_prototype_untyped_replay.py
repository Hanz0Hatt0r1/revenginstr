from __future__ import annotations

import copy
import csv
import gzip
import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.prototype_evaluation import evaluate_prototypes
from revenginstr.prototype_inference import infer_prototypes

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/ghidra-untyped-prototype"


def _jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _validate(schema_name: str, row: dict) -> None:
    schema = json.loads((ROOT / "schemas" / schema_name).read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(row)


def test_untyped_ghidra_replay_propagates_only_exact_parameter_root() -> None:
    decompiler_path = FIXTURE / "decompiler-parameters.jsonl"
    calls_path = FIXTURE / "call-observations.jsonl"
    roots_path = FIXTURE / "prototype-parameter-roots.tsv"
    decompiler = _jsonl(decompiler_path)
    by_name = {row["name"]: row for row in decompiler}
    callee = by_name["mystery_mutate"]
    caller = by_name["mystery_caller"]
    assert hashlib.sha256((FIXTURE / "untyped.o").read_bytes()).hexdigest() == callee["program_sha256"]
    assert all(row["signature_source"] == "DEFAULT" for row in decompiler)
    assert callee["parameters"][0]["type"]["kind"] == "pointer"
    assert callee["parameters"][1]["type"]["kind"] == "scalar"
    assert caller["parameters"][0]["type"] == {
        "kind": "unknown", "name": "undefined4", "path": "/undefined4", "width_bytes": 4,
    }
    assert caller["parameters"][0]["is_type_locked"] is False

    for row in decompiler:
        _validate("ghidra-decompiler-parameters-v1.schema.json", row)
    call = _jsonl(calls_path)[0]
    _validate("direct-call-argument-observation-v1.schema.json", call)
    with roots_path.open(encoding="utf-8", newline="") as handle:
        roots = list(csv.DictReader(handle, delimiter="\t"))
    root = roots[0]
    root_schema = json.loads((ROOT / "schemas/ghidra-caller-argument-parameter-root-v3.schema.json").read_text())
    Draft202012Validator(root_schema).validate(root)
    assert (root["caller_entry"], root["caller_call_site"], root["callee_entry"]) == (
        call["caller_entry"], call["call_address"], call["callee_entry"],
    )
    with (FIXTURE / "caller-arguments.tsv").open(encoding="utf-8", newline="") as handle:
        argument_rows = list(csv.DictReader(handle, delimiter="\t"))
    argument_node = next(
        row for row in argument_rows
        if row["row_type"] == "node" and row["caller_call_site"] == root["caller_call_site"]
    )
    assert argument_node["node_id"] == root["argument_node_id"]
    assert argument_node["node_token"] == call["arguments"][0]["value_token"]

    coverage = json.loads((FIXTURE / "coverage.json").read_text(encoding="utf-8"))
    _validate("function-prototype-evidence-coverage-v1.schema.json", coverage)
    assert coverage["full_program_coverage"] is True

    gold = _jsonl(FIXTURE / "gold.jsonl")
    gold_schema = json.loads((ROOT / "schemas/function-prototype-gold-v1.schema.json").read_text())
    for row in gold:
        Draft202012Validator(gold_schema).validate(row)
        assert row["program_sha256"] == hashlib.sha256((FIXTURE / "untyped.o").read_bytes()).hexdigest()
    source_sha = hashlib.sha256((FIXTURE / "untyped.c").read_bytes()).hexdigest()
    index_path = FIXTURE / "functions.tsv.gz"
    index_sha = hashlib.sha256(index_path.read_bytes()).hexdigest()
    source_lines = (FIXTURE / "untyped.c").read_text(encoding="utf-8").splitlines()
    with gzip.open(index_path, "rt", encoding="utf-8", newline="") as handle:
        indexed_functions = list(csv.DictReader(handle, delimiter="\t"))
    for row in gold:
        function = next(item for item in indexed_functions if item["entry"] == row["function_entry"])
        source_ref = next(ref for ref in row["evidence_refs"] if ref["source_format"] == "C11 function definition/1")
        index_ref = next(ref for ref in row["evidence_refs"] if ref["source_format"] == "REVENGINSTR.GhidraProgramIndex.Functions/1")
        assert source_ref["artifact_sha256"] == source_sha
        assert function["name"] in source_lines[source_ref["record_index"] - 1]
        assert index_ref["artifact_sha256"] == index_sha
        assert index_ref["record_index"] in {1, 2}
        assert indexed_functions[index_ref["record_index"] - 1] == function

    without_roots = infer_prototypes(decompiler_path, calls_path)
    with_roots = infer_prototypes(decompiler_path, calls_path, roots_path)
    caller_without = next(row for row in without_roots if row["function_entry"] == caller["function_entry"])
    caller_with = next(row for row in with_roots if row["function_entry"] == caller["function_entry"])
    assert caller_without["candidates"][0]["parameters"][0]["kind"] == "unknown"
    parameter = caller_with["candidates"][0]["parameters"][0]
    assert caller_with["status"] == "review"
    assert parameter["kind"] == "pointer"
    assert {ref["source_format"] for ref in parameter["evidence_refs"]} == {
        "REVENGINSTR.GhidraDecompilerParameters/1",
        "REVENGINSTR.DirectCallArgumentObservation/1",
        "REVENGINSTR.GhidraCallerArgumentParameterRoot/3",
    }
    hypothesis_schema = json.loads((ROOT / "schemas/function-prototype-hypothesis-v1.schema.json").read_text())
    for row in with_roots:
        Draft202012Validator(hypothesis_schema).validate(row)
    assert with_roots == _jsonl(FIXTURE / "hypotheses.jsonl")

    evaluation_schema = json.loads((ROOT / "schemas/function-prototype-evaluation-v1.schema.json").read_text())
    evaluation = evaluate_prototypes(FIXTURE / "hypotheses.jsonl", FIXTURE / "gold.jsonl")
    assert evaluation["functions_evaluated"] == 2
    assert evaluation["high_confidence_candidate_count"] == 0
    assert evaluation["per_property"]["parameter_count"]["accuracy"] == 1.0
    assert evaluation["per_property"]["parameters"]["accuracy"] == 1.0
    assert evaluation["per_property"]["return_value"]["accuracy"] == 0.5
    Draft202012Validator(evaluation_schema).validate(evaluation)
    assert evaluation == json.loads((FIXTURE / "evaluation.json").read_text(encoding="utf-8"))


def test_root_identity_mismatch_and_conflicting_callee_types_are_preserved(tmp_path: Path) -> None:
    functions = _jsonl(FIXTURE / "decompiler-parameters.jsonl")
    calls = _jsonl(FIXTURE / "call-observations.jsonl")
    root_lines = (FIXTURE / "prototype-parameter-roots.tsv").read_text(encoding="utf-8").splitlines()
    bad_root = tmp_path / "wrong-program.tsv"
    bad_root.write_text("\n".join([root_lines[0], root_lines[1].replace("\tuntyped.o\t", "\tother.o\t")]) + "\n")
    with pytest.raises(ValueError, match="program identity"):
        infer_prototypes(FIXTURE / "decompiler-parameters.jsonl", FIXTURE / "call-observations.jsonl", bad_root)

    scalar_callee = copy.deepcopy(functions[0])
    scalar_callee.update({
        "plan_id": "scalar-callee", "requested_entry": "00010030",
        "function_entry": "00010030", "name": "mystery_scalar",
        "parameter_count": 1,
        "parameters": [{**copy.deepcopy(functions[0]["parameters"][1]), "index": 0}],
        "return_type": copy.deepcopy(functions[0]["parameters"][1]["type"]),
    })
    functions.append(scalar_callee)
    decompiler_path = tmp_path / "decompiler.jsonl"
    decompiler_path.write_text("".join(json.dumps(row) + "\n" for row in functions), encoding="utf-8")

    scalar_call = copy.deepcopy(calls[0])
    scalar_call.update({"callee_entry": "00010030", "call_address": "0001002f", "call_time": 30})
    scalar_call["arguments"] = [{"index": 0, "value_token": "input:Stack[0x4]:4", "width_bytes": 4}]
    scalar_call["argument_count"] = 1
    calls_path = tmp_path / "calls.jsonl"
    calls_path.write_text("".join(json.dumps(row) + "\n" for row in [*calls, scalar_call]), encoding="utf-8")

    scalar_root = root_lines[1].replace("\t00010000\t0\t00010017\t0001001f\t", "\t00010030\t0\t00010017\t0001002f\t")
    roots_path = tmp_path / "roots.tsv"
    roots_path.write_text("\n".join([root_lines[0], root_lines[1], scalar_root]) + "\n", encoding="utf-8")
    result = infer_prototypes(decompiler_path, calls_path, roots_path)
    caller = next(row for row in result if row["function_entry"] == "00010017")
    assert caller["status"] == "conflicted"
    assert caller["candidates"][0]["parameters"][0]["kind"] == "unknown"
    assert [conflict["reason"] for conflict in caller["conflicts"]] == ["evidence_conflict"]


def test_direct_root_types_propagate_through_multiple_callers(tmp_path: Path) -> None:
    functions = _jsonl(FIXTURE / "decompiler-parameters.jsonl")
    wrapper = copy.deepcopy(functions[1])
    wrapper.update({
        "plan_id": "wrapper", "requested_entry": "00010030",
        "function_entry": "00010030", "name": "mystery_wrapper",
    })
    functions.append(wrapper)
    decompiler_path = tmp_path / "decompiler.jsonl"
    decompiler_path.write_text("".join(json.dumps(row) + "\n" for row in functions), encoding="utf-8")

    calls = _jsonl(FIXTURE / "call-observations.jsonl")
    outer_call = copy.deepcopy(calls[0])
    outer_call.update({
        "caller_entry": "00010030", "callee_entry": "00010017",
        "call_address": "0001002f", "call_time": 20,
    })
    calls.append(outer_call)
    calls_path = tmp_path / "calls.jsonl"
    calls_path.write_text("".join(json.dumps(row) + "\n" for row in calls), encoding="utf-8")

    with (FIXTURE / "prototype-parameter-roots.tsv").open(encoding="utf-8", newline="") as handle:
        root_rows = list(csv.reader(handle, delimiter="\t"))
    outer_root = root_rows[1].copy()
    outer_root[3:8] = ["wrapper-to-caller", "00010017", "0", "00010030", "0001002f"]
    # The v3 columns between the callee entry and caller entry include the callee formal index.
    roots_path = tmp_path / "roots.tsv"
    roots_path.write_text(
        "\n".join(["\t".join(root_rows[0]), "\t".join(root_rows[1]), "\t".join(outer_root)]) + "\n",
        encoding="utf-8",
    )
    rows = infer_prototypes(decompiler_path, calls_path, roots_path)
    propagated = next(row for row in rows if row["function_entry"] == "00010030")
    assert propagated["candidates"][0]["parameters"][0]["kind"] == "pointer"
    assert sum(
        ref["source_format"] == "REVENGINSTR.GhidraCallerArgumentParameterRoot/3"
        for ref in propagated["candidates"][0]["parameters"][0]["evidence_refs"]
    ) == 2
