from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.ml.accept_error_router import identity_sha256, sha256_file
from revenginstr.ml.accept_error_router_gate import FORMAT, evaluate_gate


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def fixture_files(tmp_path: Path) -> tuple[Path, Path, Path]:
    training = [
        {"id": f"train-{index}", "family_id": f"train-family-{index}", "truth": "a"}
        for index in range(4)
    ]
    training_path = tmp_path / "training.jsonl"
    write_jsonl(training_path, training)
    router_path = tmp_path / "router.json"
    router_path.write_text(json.dumps({
        "format": "REVENGINSTR.AcceptErrorRouter/1",
        "threshold": 0.5,
        "policy": {
            "scope": "base_accept_only",
            "below_threshold_action": "escalate",
            "non_accept_action": "preserve",
            "class_prediction_action": "preserve",
            "promotions_allowed": False,
        },
        "source": {
            "base_oof_sha256": sha256_file(training_path),
            "base_oof_rows": len(training),
            "base_oof_id_sha256": identity_sha256([row["id"] for row in training]),
            "base_oof_family_sha256": identity_sha256([row["family_id"] for row in training]),
        },
    }), encoding="utf-8")
    routed_path = tmp_path / "routed.jsonl"
    routed = []
    for index in range(20):
        accepted = index < 12
        routed.append({
            "id": f"gate-{index}",
            "family_id": f"gate-family-{index}",
            "truth": "a",
            "prediction": "a",
            "base_action": "accept" if accepted or index < 16 else "review",
            "action": "accept" if accepted else ("escalate" if index < 16 else "review"),
            "accept_error_router_format": "REVENGINSTR.AcceptErrorRouter/1",
            "accept_error_router_reason": (
                "accept_score_at_or_above_threshold" if accepted
                else "accept_score_below_threshold" if index < 16
                else "base_action_preserved"
            ),
            "accept_correctness_probability": 0.9 if accepted else 0.2 if index < 16 else None,
            "critical_case": index == 0,
            "evidence_conflict_detected": False,
            "population": "ood" if index >= 16 else "in_distribution",
            "external_evidence_present": index % 2 == 0,
        })
    write_jsonl(routed_path, routed)
    return routed_path, router_path, training_path


def test_frozen_router_gate_passes_only_for_independent_safe_holdout(tmp_path: Path) -> None:
    routed, router, training = fixture_files(tmp_path)
    report = evaluate_gate(routed, router, training)
    assert report["format"] == FORMAT
    assert report["gate_pass"] is True
    assert report["metrics"]["accepted_precision"] == 1.0
    assert report["metrics"]["coverage"] == 0.6
    assert report["metrics"]["critical_false_accept_rate"] == 0.0
    assert report["provenance"]["training_gate_family_overlap"] == 0
    assert set(report["coverage_by_population"]) == {"in_distribution", "ood"}
    schemas = Path(__file__).resolve().parents[1] / "schemas"
    report_schema = json.loads((schemas / "frozen-accept-router-gate-v1.schema.json").read_text(encoding="utf-8"))
    row_schema = json.loads((schemas / "frozen-accept-router-gate-row-v1.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator(report_schema).validate(report)
    Draft202012Validator(row_schema).validate(json.loads(routed.read_text(encoding="utf-8").splitlines()[0]))


def test_gate_fails_for_conflict_acceptance_and_family_overlap(tmp_path: Path) -> None:
    routed, router, training = fixture_files(tmp_path)
    rows = [json.loads(line) for line in routed.read_text(encoding="utf-8").splitlines()]
    rows[0]["evidence_conflict_detected"] = True
    rows[0]["family_id"] = "train-family-0"
    write_jsonl(routed, rows)
    report = evaluate_gate(routed, router, training)
    assert report["gate_pass"] is False
    assert report["metrics"]["evidence_conflict_accepts"] == 1
    assert report["provenance"]["training_gate_family_overlap"] == 1
    assert report["checks"]["evidence_conflicts_never_accept"] is False


def test_gate_rejects_router_source_mismatch(tmp_path: Path) -> None:
    routed, router, training = fixture_files(tmp_path)
    training.write_text(training.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="hash does not match"):
        evaluate_gate(routed, router, training)


def test_gate_requires_explicit_critical_and_conflict_annotations(tmp_path: Path) -> None:
    routed, router, training = fixture_files(tmp_path)
    rows = [json.loads(line) for line in routed.read_text(encoding="utf-8").splitlines()]
    rows[0].pop("evidence_conflict_detected")
    write_jsonl(routed, rows)
    with pytest.raises(ValueError, match="evidence_conflict_detected"):
        evaluate_gate(routed, router, training)


def test_gate_fails_when_accept_precision_misses_minimum(tmp_path: Path) -> None:
    routed, router, training = fixture_files(tmp_path)
    rows = [json.loads(line) for line in routed.read_text(encoding="utf-8").splitlines()]
    rows[0]["truth"] = "wrong"
    write_jsonl(routed, rows)
    report = evaluate_gate(routed, router, training)
    assert report["metrics"]["accepted_precision"] < 0.97
    assert report["checks"]["accepted_precision_meets_minimum"] is False
    assert report["gate_pass"] is False
