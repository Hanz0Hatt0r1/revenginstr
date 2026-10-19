from __future__ import annotations

import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator

from revenginstr.prototype_evaluation import evaluate_prototypes
from revenginstr.prototype_inference import infer_prototypes

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/ghidra-indirect-call-v4"
HYPOTHESIS_SCHEMA = json.loads((ROOT / "schemas/function-prototype-hypothesis-v1.schema.json").read_text())
GOLD_SCHEMA = json.loads((ROOT / "schemas/function-prototype-gold-v1.schema.json").read_text())
EVALUATION_SCHEMA = json.loads((ROOT / "schemas/function-prototype-evaluation-v2.schema.json").read_text())


def _jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def test_exact_static_indirect_return_replay_emits_a_possible_alternative() -> None:
    rows = infer_prototypes(
        FIXTURE / "decompiler-parameters.jsonl",
        FIXTURE / "direct-call-observations.jsonl",
        indirect_call_evidence_path=FIXTURE / "callind.jsonl",
        function_pcode_flow_paths=[FIXTURE / "flow.tsv"],
    )
    assert rows == _jsonl(FIXTURE / "return-shape-hypotheses.jsonl")
    for row in rows:
        Draft202012Validator(HYPOTHESIS_SCHEMA).validate(row)

    caller = next(row for row in rows if row["function_entry"] == "0040100f")
    assert caller["candidates"][0]["return_value"] == {"kind": "void", "width_bytes": None}
    suggestion = caller["candidates"][1]
    assert suggestion["candidate_id"] == "possible-indirect-call-return"
    assert suggestion["return_value"] == {"kind": "scalar", "width_bytes": 4}
    assert suggestion["confidence"] == 0.15
    formats = {ref["source_format"] for ref in suggestion["evidence_refs"]}
    assert formats == {
        "REVENGINSTR.GhidraDecompilerParameters/1",
        "REVENGINSTR.GhidraIndirectCallEvidence/4",
        "REVENGINSTR.GhidraFunctionPcodeFlow/1",
    }

    gold = _jsonl(FIXTURE / "return-shape-gold.jsonl")
    Draft202012Validator(GOLD_SCHEMA).validate(gold[0])
    binary_sha = hashlib.sha256((FIXTURE / "callind.elf").read_bytes()).hexdigest()
    source_sha = hashlib.sha256((FIXTURE / "callind.c").read_bytes()).hexdigest()
    decompiler_sha = hashlib.sha256((FIXTURE / "decompiler-parameters.jsonl").read_bytes()).hexdigest()
    source_ref = next(ref for ref in gold[0]["evidence_refs"] if ref["source_format"] == "C11 function definition/1")
    decompiler_ref = next(ref for ref in gold[0]["evidence_refs"] if ref["source_format"] == "REVENGINSTR.GhidraDecompilerParameters/1")
    assert gold[0]["program_sha256"] == binary_sha
    assert source_ref["artifact_sha256"] == source_sha
    assert source_ref["record_index"] == 9
    assert decompiler_ref["artifact_sha256"] == decompiler_sha
    assert decompiler_ref["record_index"] == 2

    evaluation = evaluate_prototypes(
        FIXTURE / "return-shape-hypotheses.jsonl",
        FIXTURE / "return-shape-gold.jsonl",
        format_version=2,
    )
    Draft202012Validator(EVALUATION_SCHEMA).validate(evaluation)
    assert evaluation == json.loads((FIXTURE / "return-shape-evaluation.json").read_text())
    assert evaluation["per_property"]["return_value"]["coverage"] == 0.5
    assert evaluation["per_property"]["return_value"]["known_accuracy"] == 1.0
    assert evaluation["high_confidence_candidate_count"] == 0


def test_unresolved_indirect_target_does_not_propagate_return_shape(tmp_path: Path) -> None:
    row = _jsonl(FIXTURE / "callind.jsonl")[0]
    row["target_resolution"] = {
        "status": "unreadable_pointer", "slot_address": "0x00403000", "function_entry": None,
    }
    row["parameter_roots"] = []
    evidence = tmp_path / "unresolved-callind.jsonl"
    evidence.write_text(json.dumps(row) + "\n", encoding="utf-8")
    rows = infer_prototypes(
        FIXTURE / "decompiler-parameters.jsonl",
        FIXTURE / "direct-call-observations.jsonl",
        indirect_call_evidence_path=evidence,
        function_pcode_flow_paths=[FIXTURE / "flow.tsv"],
    )
    caller = next(row for row in rows if row["function_entry"] == "0040100f")
    assert all(candidate["candidate_id"] != "possible-indirect-call-return" for candidate in caller["candidates"])
