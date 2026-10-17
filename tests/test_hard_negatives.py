from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.ml import SELECTIVE_CLASSIFIER_FORMAT
from revenginstr.ml.hard_negatives import build_hard_negative_set, main

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas/classifier-hard-negative-set-v1.schema.json"


def prediction(record_id: str, family_id: str, truth: str, predicted: str, confidence: float, action: str) -> dict:
    return {
        "format": SELECTIVE_CLASSIFIER_FORMAT,
        "id": record_id,
        "family_id": family_id,
        "truth": truth,
        "prediction": predicted,
        "correct": truth == predicted,
        "confidence": confidence,
        "action": action,
    }


def inputs() -> tuple[dict, list[dict], bytes]:
    rows = [
        prediction("accepted-wrong", "family-1", "alpha", "beta", 0.96, "accept"),
        prediction("review-wrong", "family-2", "alpha", "beta", 0.99, "review"),
        prediction("low-confidence", "family-3", "beta", "alpha", 0.80, "accept"),
        prediction("correct", "family-4", "beta", "beta", 0.99, "accept"),
    ]
    encoded = "".join(json.dumps(row) + "\n" for row in rows).encode()
    report = {
        "format": "REVENGINSTR.SelectiveThresholdEvaluation/1",
        "source": {
            "classifier_format": SELECTIVE_CLASSIFIER_FORMAT,
            "evaluation_predictions_sha256": hashlib.sha256(encoded).hexdigest(),
            "evaluation_rows": 4,
            "evaluation_families": 4,
            "family_disjoint": True,
        },
        "classes": {"alpha": {}, "beta": {}},
    }
    return report, rows, encoded


def build(
    report: dict, rows: list[dict], *, actions: list[str] | None = None,
    threshold: float = 0.9, prediction_sha: str | None = None,
) -> dict:
    return build_hard_negative_set(
        report,
        rows,
        minimum_confidence=threshold,
        actions=actions or ["accept"],
        evaluation_report_sha256="a" * 64,
        predictions_sha256=prediction_sha or report["source"]["evaluation_predictions_sha256"],
    )


def test_hard_negative_set_selects_only_requested_evaluation_errors() -> None:
    report, rows, _ = inputs()
    result = build(report, rows)

    Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))).validate(result)
    assert result["source"]["family_disjoint"] is True
    assert result["selection"] == {
        "minimum_confidence": 0.9,
        "actions": ["accept"],
        "selected_rows": 1,
        "selected_families": 1,
    }
    assert result["examples"] == [{
        "id": "accepted-wrong", "family_id": "family-1", "truth": "alpha",
        "prediction": "beta", "confidence": 0.96, "action": "accept",
    }]


def test_hard_negative_selection_can_include_other_actions_or_be_empty() -> None:
    report, rows, _ = inputs()
    review = build(report, rows, actions=["review"])
    assert [row["id"] for row in review["examples"]] == ["review-wrong"]
    assert build(report, rows, threshold=1.0)["examples"] == []


@pytest.mark.parametrize("mutation, message", [
    (lambda report, rows: report["source"].update(family_disjoint=False), "does not match"),
    (lambda report, rows: report["source"].update(evaluation_rows=True), "invalid population counts"),
    (lambda report, rows: rows[0].update(correct=True), "correct flag disagrees"),
    (lambda report, rows: rows[0].update(action="other"), "invalid route action"),
    (lambda report, rows: rows.append(dict(rows[0])), "invalid or duplicate id"),
    (lambda report, rows: rows[0].update(confidence=float("nan")), "invalid calibrated confidence"),
])
def test_hard_negative_selection_rejects_invalid_or_unpinned_data(mutation, message: str) -> None:
    report, rows, _ = inputs()
    mutation(report, rows)
    with pytest.raises(ValueError, match=message):
        build(report, rows)


def test_hard_negative_cli_records_hashes_and_threshold(tmp_path: Path, capsys) -> None:
    report, _, prediction_bytes = inputs()
    report_path = tmp_path / "evaluation-report.json"
    predictions_path = tmp_path / "evaluation.jsonl"
    output = tmp_path / "nested" / "hard-negatives.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    predictions_path.write_bytes(prediction_bytes)

    assert main([
        str(report_path), str(predictions_path), "--minimum-confidence", "0.9", "--output", str(output),
    ]) == 0
    result = json.loads(output.read_text(encoding="utf-8"))
    Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))).validate(result)
    assert result["source"]["evaluation_report_sha256"] == hashlib.sha256(report_path.read_bytes()).hexdigest()
    assert result["source"]["evaluation_predictions_sha256"] == hashlib.sha256(prediction_bytes).hexdigest()
    assert "retained hard negatives: 1" in capsys.readouterr().out


def test_hard_negative_set_rejects_prediction_hash_mismatch() -> None:
    report, rows, _ = inputs()
    with pytest.raises(ValueError, match="does not match"):
        build(report, rows, prediction_sha="0" * 64)
