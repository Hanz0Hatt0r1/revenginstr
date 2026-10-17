from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.ml import SELECTIVE_CLASSIFIER_FORMAT
from revenginstr.ml.error_buckets import build_error_buckets, main


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "classifier-error-buckets-v1.schema.json"


def prediction(record_id: str, family_id: str, truth: str, predicted: str, action: str, confidence: float) -> dict:
    return {
        "format": SELECTIVE_CLASSIFIER_FORMAT,
        "id": record_id,
        "family_id": family_id,
        "truth": truth,
        "prediction": predicted,
        "correct": truth == predicted,
        "action": action,
        "confidence": confidence,
    }


def input_rows() -> tuple[dict, list[dict], str]:
    rows = [
        prediction("e1", "family-1", "alpha", "beta", "accept", 0.95),
        prediction("e2", "family-2", "alpha", "beta", "review", 0.70),
        prediction("e3", "family-3", "beta", "alpha", "escalate", 0.60),
        prediction("c1", "family-4", "alpha", "alpha", "review", 0.80),
    ]
    encoded = "".join(json.dumps(row) + "\n" for row in rows).encode("utf-8")
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
    return report, rows, encoded.decode("utf-8")


def test_error_buckets_group_confusion_pairs_and_route_actions() -> None:
    report, rows, _ = input_rows()
    result = build_error_buckets(
        report, rows, evaluation_report_sha256="a" * 64,
        predictions_sha256=report["source"]["evaluation_predictions_sha256"],
    )

    Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))).validate(result)
    assert result["source"]["family_disjoint"] is True
    assert result["error_rows"] == 3
    assert result["error_rate"] == 0.75
    assert result["accepted_error_rows"] == 1
    first, second = result["error_buckets"]
    assert (first["truth"], first["prediction"], first["error_count"]) == ("alpha", "beta", 2)
    assert first["family_count"] == 2
    assert first["action_counts"] == {"accept": 1, "review": 1, "escalate": 0}
    assert first["confidence"]["mean"] == pytest.approx(0.825)
    assert (second["truth"], second["prediction"], second["error_count"]) == ("beta", "alpha", 1)


@pytest.mark.parametrize("mutation, message", [
    (lambda report, rows: report["source"].update(evaluation_predictions_sha256="0" * 64), "does not match"),
    (lambda report, rows: report["source"].update(family_disjoint=False), "does not match"),
    (lambda report, rows: rows[0].update(action="unknown"), "invalid route action"),
    (lambda report, rows: rows[0].update(correct=True), "correct flag disagrees"),
])
def test_error_buckets_reject_mismatched_or_invalid_rows(mutation, message: str) -> None:
    report, rows, _ = input_rows()
    expected_predictions_sha256 = report["source"]["evaluation_predictions_sha256"]
    mutation(report, rows)

    with pytest.raises(ValueError, match=message):
        build_error_buckets(
            report, rows, evaluation_report_sha256="a" * 64,
            predictions_sha256=expected_predictions_sha256,
        )


def test_error_bucket_cli_writes_report_with_source_hashes(tmp_path: Path, capsys) -> None:
    report, rows, encoded = input_rows()
    report_path = tmp_path / "evaluation-report.json"
    prediction_path = tmp_path / "evaluation.jsonl"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    prediction_path.write_text(encoded, encoding="utf-8")
    output = tmp_path / "nested" / "errors.json"

    assert main([
        str(report_path), str(prediction_path), "--output", str(output)
    ]) == 0
    result = json.loads(output.read_text(encoding="utf-8"))
    Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))).validate(result)
    assert result["source"]["evaluation_report_sha256"] == hashlib.sha256(
        report_path.read_bytes()
    ).hexdigest()
    assert "confusion-pair buckets: 2" in capsys.readouterr().out
