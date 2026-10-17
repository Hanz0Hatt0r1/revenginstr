from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.ml import SELECTIVE_CLASSIFIER_FORMAT
from revenginstr.ml.subgroup_audit import (
    SUBGROUP_FORMAT,
    build_subgroup_audit,
    main,
)


ROOT = Path(__file__).resolve().parents[1]
REPORT_SCHEMA = ROOT / "schemas/selective-subgroup-audit-v1.schema.json"
ROW_SCHEMA = ROOT / "schemas/evaluation-subgroup-v1.schema.json"


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


def inputs() -> tuple[dict, list[dict], list[dict], bytes, bytes]:
    rows = [
        prediction("p1", "family-1", "alpha", "alpha", "accept", 0.9),
        prediction("p2", "family-2", "alpha", "beta", "accept", 0.8),
        prediction("p3", "family-3", "beta", "beta", "review", 0.7),
        prediction("p4", "family-4", "beta", "alpha", "escalate", 0.6),
    ]
    subgroups = [
        {"format": SUBGROUP_FORMAT, "id": "p1", "subgroup": "cohort-a"},
        {"format": SUBGROUP_FORMAT, "id": "p2", "subgroup": "cohort-a"},
        {"format": SUBGROUP_FORMAT, "id": "p3", "subgroup": "cohort-b"},
        {"format": SUBGROUP_FORMAT, "id": "p4", "subgroup": "cohort-b"},
    ]
    prediction_bytes = b"".join((json.dumps(row) + "\n").encode() for row in rows)
    subgroup_bytes = b"".join((json.dumps(row) + "\n").encode() for row in subgroups)
    report = {
        "format": "REVENGINSTR.SelectiveThresholdEvaluation/1",
        "source": {
            "classifier_format": SELECTIVE_CLASSIFIER_FORMAT,
            "evaluation_predictions_sha256": hashlib.sha256(prediction_bytes).hexdigest(),
            "evaluation_rows": len(rows),
            "evaluation_families": len(rows),
            "family_disjoint": True,
        },
        "bin_count": 2,
        "classes": {"alpha": {}, "beta": {}},
    }
    return report, rows, subgroups, prediction_bytes, subgroup_bytes


def build(report: dict, rows: list[dict], groups: list[dict], prediction_sha: str | None = None) -> dict:
    return build_subgroup_audit(
        report,
        rows,
        groups,
        evaluation_report_sha256="a" * 64,
        predictions_sha256=prediction_sha or report["source"]["evaluation_predictions_sha256"],
        subgroups_sha256="b" * 64,
    )


def test_subgroup_audit_reports_metrics_for_caller_named_groups() -> None:
    report, rows, groups, _, _ = inputs()
    result = build(report, rows, groups)

    Draft202012Validator(json.loads(REPORT_SCHEMA.read_text(encoding="utf-8"))).validate(result)
    for row in groups:
        Draft202012Validator(json.loads(ROW_SCHEMA.read_text(encoding="utf-8"))).validate(row)
    assert result["source"]["family_disjoint"] is True
    assert result["source"]["subgroup_count"] == 2
    first = result["groups"]["cohort-a"]
    assert (first["rows"], first["correct_rows"], first["accuracy"]) == (2, 1, 0.5)
    assert first["action_counts"] == {"accept": 2, "review": 0, "escalate": 0}
    assert first["accepted_rows"] == 2
    assert first["accepted_precision"] == 0.5
    assert first["accepted_coverage"] == 1.0
    assert first["class_counts"]["alpha"] == {
        "truth_rows": 2, "predicted_rows": 1, "true_positive_rows": 1,
    }
    assert first["calibration"]["brier_score"] == pytest.approx(0.325)
    assert first["calibration"]["expected_calibration_error"] == pytest.approx(0.35)
    second = result["groups"]["cohort-b"]
    assert second["accepted_rows"] == 0
    assert second["accepted_precision"] is None
    assert second["accepted_coverage"] == 0.0


@pytest.mark.parametrize("mapping_change, message", [
    (lambda groups: groups.pop(), "cover every evaluation id"),
    (lambda groups: groups.append(dict(groups[0])), "invalid, duplicate, or unknown id"),
    (lambda groups: groups[0].update(id="missing"), "invalid, duplicate, or unknown id"),
])
def test_subgroup_audit_requires_exact_mapping(mapping_change, message: str) -> None:
    report, rows, groups, _, _ = inputs()
    mapping_change(groups)
    with pytest.raises(ValueError, match=message):
        build(report, rows, groups)


@pytest.mark.parametrize("change, message", [
    (lambda report, rows: report["source"].update(family_disjoint=False), "does not match"),
    (lambda report, rows: report["source"].update(evaluation_rows=True), "population counts disagree"),
    (lambda report, rows: rows[0].update(correct=False), "correct flag disagrees"),
    (lambda report, rows: rows[0].update(action="unknown"), "invalid route action"),
    (lambda report, rows: rows[0].update(confidence=10 ** 10000), "invalid calibrated confidence"),
])
def test_subgroup_audit_rejects_mismatched_evaluation(change, message: str) -> None:
    report, rows, groups, _, _ = inputs()
    change(report, rows)
    with pytest.raises(ValueError, match=message):
        build(report, rows, groups)


def test_subgroup_audit_rejects_prediction_hash_mismatch() -> None:
    report, rows, groups, _, _ = inputs()
    with pytest.raises(ValueError, match="does not match"):
        build(report, rows, groups, prediction_sha="0" * 64)


def test_subgroup_audit_cli_writes_all_input_hashes(tmp_path: Path, capsys) -> None:
    report, _, _, prediction_bytes, subgroup_bytes = inputs()
    report_path = tmp_path / "threshold-evaluation.json"
    prediction_path = tmp_path / "evaluation.jsonl"
    subgroup_path = tmp_path / "subgroups.jsonl"
    output = tmp_path / "nested" / "subgroups.json"
    report_path.write_text(json.dumps(report), encoding="utf-8")
    prediction_path.write_bytes(prediction_bytes)
    subgroup_path.write_bytes(subgroup_bytes)

    assert main([
        str(report_path), str(prediction_path), str(subgroup_path), "--output", str(output),
    ]) == 0
    result = json.loads(output.read_text(encoding="utf-8"))
    Draft202012Validator(json.loads(REPORT_SCHEMA.read_text(encoding="utf-8"))).validate(result)
    assert result["source"]["evaluation_report_sha256"] == hashlib.sha256(report_path.read_bytes()).hexdigest()
    assert result["source"]["evaluation_predictions_sha256"] == hashlib.sha256(prediction_bytes).hexdigest()
    assert result["source"]["subgroups_sha256"] == hashlib.sha256(subgroup_bytes).hexdigest()
    assert "subgroups: 2" in capsys.readouterr().out
