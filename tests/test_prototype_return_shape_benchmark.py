from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

from revenginstr.prototype_evaluation import evaluate_prototypes

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures"
BENCHMARK = FIXTURES / "prototype-return-shape-benchmark"
GOLD_SCHEMA = json.loads((ROOT / "schemas/function-prototype-gold-v1.schema.json").read_text())
HYPOTHESIS_SCHEMA = json.loads((ROOT / "schemas/function-prototype-hypothesis-v1.schema.json").read_text())
EVALUATION_SCHEMA = json.loads((ROOT / "schemas/function-prototype-evaluation-v2.schema.json").read_text())


def _jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def test_combined_return_shape_benchmark_covers_both_real_replays() -> None:
    hypotheses = _jsonl(BENCHMARK / "hypotheses.jsonl")
    expected_hypotheses = [
        *_jsonl(FIXTURES / "ghidra-tail-call-return/hypotheses.jsonl"),
        *_jsonl(FIXTURES / "ghidra-indirect-call-v4/return-shape-hypotheses.jsonl"),
    ]
    assert hypotheses == expected_hypotheses
    for row in hypotheses:
        Draft202012Validator(HYPOTHESIS_SCHEMA).validate(row)
    assert {row["architecture"]["language_id"] for row in hypotheses} == {
        "x86:LE:32:default", "x86:LE:64:default",
    }

    gold = _jsonl(BENCHMARK / "gold.jsonl")
    expected_gold = [
        *_jsonl(FIXTURES / "ghidra-tail-call-return/gold.jsonl"),
        *_jsonl(FIXTURES / "ghidra-indirect-call-v4/return-shape-gold.jsonl"),
    ]
    for row in expected_gold:
        row["dataset_id"] = "prototype-return-shape-replays"
        row["split_id"] = "ghidra12.1.2-x86-32-x86-64-v1"
    assert gold == expected_gold
    for row in gold:
        Draft202012Validator(GOLD_SCHEMA).validate(row)

    evaluation = evaluate_prototypes(
        BENCHMARK / "hypotheses.jsonl", BENCHMARK / "gold.jsonl", format_version=2,
    )
    Draft202012Validator(EVALUATION_SCHEMA).validate(evaluation)
    assert evaluation == json.loads((BENCHMARK / "evaluation.json").read_text())
    assert evaluation["functions_evaluated"] == 3
    assert evaluation["candidate_count"] == 5
    assert evaluation["high_confidence_candidate_count"] == 0
    assert evaluation["per_property"]["return_value"]["coverage"] == 0.6
    assert evaluation["per_property"]["return_value"]["known_accuracy"] == 1.0
