from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.ml import SELECTIVE_CLASSIFIER_FORMAT
from revenginstr.ml.threshold_sweep import build_threshold_sweep, main


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "selective-threshold-sweep-v1.schema.json"


def prediction(record_id: str, truth: str, predicted: str, confidence: float) -> dict:
    return {
        "format": SELECTIVE_CLASSIFIER_FORMAT,
        "id": record_id,
        "family_id": f"family-{record_id}",
        "truth": truth,
        "prediction": predicted,
        "correct": truth == predicted,
        "confidence": confidence,
    }


def inputs() -> tuple[dict, list[dict]]:
    rows = [
        prediction("a1", "alpha", "alpha", 0.9),
        prediction("a2", "alpha", "alpha", 0.8),
        prediction("b1", "beta", "alpha", 0.7),
        prediction("b2", "beta", "beta", 0.85),
    ]
    manifest = {
        "format": SELECTIVE_CLASSIFIER_FORMAT,
        "classes": ["alpha", "beta", "gamma"],
        "calibration": {"source": "family_grouped_oof"},
        "functions": len(rows),
        "families": 4,
        "class_distribution": dict(sorted(Counter(row["truth"] for row in rows).items())),
    }
    return manifest, rows


def test_threshold_sweep_reports_classwise_precision_and_coverage() -> None:
    manifest, rows = inputs()
    result = build_threshold_sweep(
        manifest, rows, targets=[0.9, 0.65], min_examples=2,
        manifest_sha256="a" * 64, predictions_sha256="b" * 64,
    )

    Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))).validate(result)
    alpha = result["classes"]["alpha"]
    assert alpha["predicted_examples"] == 3
    assert alpha["baseline_precision"] == pytest.approx(2 / 3)
    assert alpha["sweeps"][0] == {
        "target_precision": 0.65,
        "status": "feasible",
        "threshold": 0.7,
        "precision": pytest.approx(2 / 3),
        "accepted_examples": 3,
        "coverage": 1.0,
    }
    assert alpha["sweeps"][1]["threshold"] == 0.8
    assert alpha["sweeps"][1]["coverage"] == pytest.approx(2 / 3)
    assert result["classes"]["beta"]["sweeps"][0]["status"] == "insufficient_examples"
    assert result["classes"]["gamma"]["sweeps"][0]["status"] == "no_predictions"
    assert result["targets"] == [0.65, 0.9]


def test_threshold_sweep_marks_targets_unmet_when_minimum_support_blocks_them() -> None:
    manifest, rows = inputs()
    result = build_threshold_sweep(
        manifest, rows, targets=[1.0], min_examples=3,
        manifest_sha256="a" * 64, predictions_sha256="b" * 64,
    )

    assert result["classes"]["alpha"]["sweeps"][0]["status"] == "target_unmet"


@pytest.mark.parametrize("mutation, message", [
    (lambda manifest, rows: manifest["calibration"].update(source="random_split"), "family-grouped OOF"),
    (lambda manifest, rows: rows[0].update(correct=False), "correct flag disagrees"),
    (lambda manifest, rows: rows[1].update(id=rows[0]["id"]), "duplicate id"),
    (lambda manifest, rows: manifest.update(functions=99), "row count disagrees"),
])
def test_threshold_sweep_rejects_inconsistent_or_non_oof_inputs(mutation, message: str) -> None:
    manifest, rows = inputs()
    mutation(manifest, rows)

    with pytest.raises(ValueError, match=message):
        build_threshold_sweep(
            manifest, rows, targets=[0.9], min_examples=1,
            manifest_sha256="a" * 64, predictions_sha256="b" * 64,
        )


def test_threshold_sweep_cli_hashes_and_writes_report(tmp_path: Path, capsys) -> None:
    manifest, rows = inputs()
    manifest_path = tmp_path / "manifest.json"
    predictions_path = tmp_path / "oof.jsonl"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    predictions_path.write_text(
        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
    )
    output = tmp_path / "nested" / "sweep.json"

    assert main([
        str(manifest_path), str(predictions_path), "--output", str(output),
        "--target-precision", "0.9", "--min-examples", "1",
    ]) == 0
    result = json.loads(output.read_text(encoding="utf-8"))
    Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))).validate(result)
    assert result["source"]["manifest_sha256"] == hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    assert result["source"]["prediction_rows"] == 4
    assert "target precision levels: 1" in capsys.readouterr().out
