from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.prototype_evaluation import evaluate_prototypes, main

ROOT = Path(__file__).resolve().parents[1]
HYPOTHESES = ROOT / "tests/fixtures/function-prototype-hypothesis/synthetic.jsonl"
GOLD = ROOT / "tests/fixtures/function-prototype-gold/synthetic.jsonl"


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_synthetic_prototype_replay_scores_only_complete_properties() -> None:
    hypothesis_schema = json.loads((ROOT / "schemas/function-prototype-hypothesis-v1.schema.json").read_text())
    gold_schema = json.loads((ROOT / "schemas/function-prototype-gold-v1.schema.json").read_text())
    evaluation_schema = json.loads((ROOT / "schemas/function-prototype-evaluation-v1.schema.json").read_text())
    for schema in (hypothesis_schema, gold_schema, evaluation_schema):
        Draft202012Validator.check_schema(schema)
    for row in read_jsonl(HYPOTHESES):
        Draft202012Validator(hypothesis_schema).validate(row)
    gold_rows = read_jsonl(GOLD)
    for row in gold_rows:
        Draft202012Validator(gold_schema).validate(row)
    source = ROOT / "tests/fixtures/function-prototype-gold/synthetic-source.jsonl"
    assert gold_rows[0]["evidence_refs"][0]["artifact_sha256"] == hashlib.sha256(
        source.read_bytes()
    ).hexdigest()

    report = evaluate_prototypes(HYPOTHESES, GOLD)

    assert report["functions_evaluated"] == 1
    assert report["high_confidence_candidate_count"] == 1
    assert report["high_confidence_candidate_compatibility"] == 1
    assert report["high_confidence_function_coverage"] == 1
    assert report["top_candidate_compatibility"] == 1
    assert report["per_property"]["parameter_count"]["accuracy"] == 0.5
    assert "receiver_parameter_index" not in report["per_property"]
    Draft202012Validator(evaluation_schema).validate(report)


def test_prototype_gold_rejects_evidence_that_cites_evaluated_hypothesis(tmp_path: Path) -> None:
    hypotheses = tmp_path / "hypotheses.jsonl"
    gold = tmp_path / "gold.jsonl"
    hypotheses.write_bytes(HYPOTHESES.read_bytes())
    row = read_jsonl(GOLD)[0]
    row["evidence_refs"][0]["artifact_sha256"] = hashlib.sha256(hypotheses.read_bytes()).hexdigest()
    gold.write_text(json.dumps(row) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="non-independent"):
        evaluate_prototypes(hypotheses, gold)


def test_prototype_evaluation_rejects_architecture_mismatch(tmp_path: Path) -> None:
    hypotheses = tmp_path / "hypotheses.jsonl"
    rows = read_jsonl(HYPOTHESES)
    rows[0]["architecture"] = {
        "language_id": "x86:LE:64:default", "pointer_width_bytes": 8, "endianness": "little",
    }
    hypotheses.write_text(json.dumps(rows[0]) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="architecture disagrees"):
        evaluate_prototypes(hypotheses, GOLD)


def test_prototype_cli_writes_evaluation(tmp_path: Path, capsys) -> None:
    output = tmp_path / "nested" / "evaluation.json"
    assert main([str(HYPOTHESES), str(GOLD), "--output", str(output)]) == 0
    assert json.loads(output.read_text(encoding="utf-8"))["format"] == "REVENGINSTR.FunctionPrototypeEvaluation/1"
    assert "high-confidence compatibility" in capsys.readouterr().out
