from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.ml import SELECTIVE_CLASSIFIER_FORMAT
from revenginstr.ml.threshold_evaluate import build_threshold_evaluation, main


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "selective-threshold-evaluation-v1.schema.json"


def prediction(record_id: str, family_id: str, truth: str, predicted: str, confidence: float) -> dict:
    return {
        "format": SELECTIVE_CLASSIFIER_FORMAT,
        "id": record_id,
        "family_id": family_id,
        "truth": truth,
        "prediction": predicted,
        "correct": truth == predicted,
        "confidence": confidence,
    }


def inputs() -> tuple[dict, list[dict], list[dict]]:
    oof_rows = [
        prediction("a1", "train-a", "alpha", "alpha", 0.95),
        prediction("a2", "train-b", "alpha", "alpha", 0.85),
        prediction("b1", "train-c", "beta", "alpha", 0.60),
        prediction("b2", "train-d", "beta", "beta", 0.90),
    ]
    evaluation_rows = [
        prediction("eval-a", "eval-a-family", "alpha", "alpha", 0.90),
        prediction("eval-b", "eval-b-family", "beta", "alpha", 0.80),
        prediction("eval-c", "eval-c-family", "alpha", "beta", 0.90),
    ]
    manifest = {
        "format": SELECTIVE_CLASSIFIER_FORMAT,
        "classes": ["alpha", "beta", "gamma"],
        "calibration": {"source": "family_grouped_oof"},
        "functions": len(oof_rows),
        "families": len(oof_rows),
        "class_distribution": dict(sorted(Counter(row["truth"] for row in oof_rows).items())),
    }
    return manifest, oof_rows, evaluation_rows


def test_family_heldout_evaluation_preserves_calibration_and_threshold_results() -> None:
    manifest, oof_rows, evaluation_rows = inputs()
    result = build_threshold_evaluation(
        manifest, oof_rows, evaluation_rows, targets=[0.9], min_train_examples=1,
        bin_count=10, manifest_sha256="a" * 64, oof_sha256="b" * 64,
        evaluation_sha256="c" * 64,
    )

    Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))).validate(result)
    assert result["source"]["family_disjoint"] is True
    assert result["source"]["training_oof_families"] == 4
    assert result["source"]["evaluation_families"] == 3
    alpha = result["classes"]["alpha"]
    assert alpha["evaluation_predictions"] == 2
    assert alpha["accuracy"] == 0.5
    assert alpha["calibration"]["brier_score"] == pytest.approx(0.325)
    assert alpha["calibration"]["expected_calibration_error"] == pytest.approx(0.45)
    assert alpha["thresholds"][0]["training_threshold"] == 0.85
    assert alpha["thresholds"][0]["precision"] == 1.0
    assert alpha["thresholds"][0]["coverage"] == 0.5
    assert result["classes"]["beta"]["thresholds"][0]["precision"] == 0.0
    assert result["classes"]["gamma"]["calibration"]["brier_score"] is None


@pytest.mark.parametrize("mutate, message", [
    (lambda rows: rows[0].update(family_id="train-a"), "family overlaps"),
    (lambda rows: rows[0].update(id="a1"), "overlapping id"),
    (lambda rows: rows[0].update(correct=False), "correct flag disagrees"),
])
def test_family_heldout_evaluation_rejects_leakage_and_bad_rows(mutate, message: str) -> None:
    manifest, oof_rows, evaluation_rows = inputs()
    mutate(evaluation_rows)

    with pytest.raises(ValueError, match=message):
        build_threshold_evaluation(
            manifest, oof_rows, evaluation_rows, targets=[0.9], min_train_examples=1,
            bin_count=5, manifest_sha256="a" * 64, oof_sha256="b" * 64,
            evaluation_sha256="c" * 64,
        )


def test_family_heldout_evaluation_cli_writes_hashed_report(tmp_path: Path, capsys) -> None:
    manifest, oof_rows, evaluation_rows = inputs()
    manifest_path = tmp_path / "manifest.json"
    oof_path = tmp_path / "oof.jsonl"
    evaluation_path = tmp_path / "evaluation.jsonl"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    oof_path.write_text("".join(json.dumps(row) + "\n" for row in oof_rows), encoding="utf-8")
    evaluation_path.write_text(
        "".join(json.dumps(row) + "\n" for row in evaluation_rows), encoding="utf-8"
    )
    output = tmp_path / "nested" / "evaluation.json"

    assert main([
        str(manifest_path), str(oof_path), str(evaluation_path), "--output", str(output),
        "--target-precision", "0.9", "--min-train-examples", "1", "--bins", "5",
    ]) == 0
    result = json.loads(output.read_text(encoding="utf-8"))
    Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))).validate(result)
    assert result["source"]["evaluation_predictions_sha256"] == hashlib.sha256(
        evaluation_path.read_bytes()
    ).hexdigest()
    assert len(result["classes"]["alpha"]["calibration"]["bins"]) == 5
    assert "family-disjoint: True" in capsys.readouterr().out
