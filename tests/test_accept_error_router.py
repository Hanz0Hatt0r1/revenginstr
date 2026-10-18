from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

from revenginstr.ml.accept_error_router import (
    FORMAT,
    route_rows,
    safe_evidence_keys,
    train_accept_error_router,
)
from revenginstr.ml.evidence_tokens import EVIDENCE_FORMAT, load_evidence


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def make_oof() -> list[dict]:
    rows: list[dict] = []
    for family in range(20):
        for member in range(5):
            prediction = "alpha" if (family + member) % 2 == 0 else "beta"
            correct = member != 0  # each family contributes one accept error
            truth = prediction if correct else ("beta" if prediction == "alpha" else "alpha")
            confidence = 0.95 if correct else 0.55
            other = 1.0 - confidence
            rows.append({
                "format": "REVENGINSTR.SelectiveClassifier/1",
                "id": f"f{family}-{member}",
                "family_id": f"family-{family}",
                "truth": truth,
                "prediction": prediction,
                "correct": correct,
                "action": "accept",
                "probabilities": {
                    prediction: confidence,
                    ("beta" if prediction == "alpha" else "alpha"): other,
                },
                "family_similarity": 0.9 if correct else 0.2,
                "competing_similarity": 0.2 if correct else 0.6,
                "contrast_margin": 0.7 if correct else -0.4,
            })
    return rows


def validate_schema(name: str, value: dict) -> None:
    schema_path = Path(__file__).resolve().parents[1] / "schemas" / name
    Draft202012Validator(json.loads(schema_path.read_text(encoding="utf-8"))).validate(value)


def test_blocked_evidence_identity_terms() -> None:
    evidence = {
        "x": {
            "callgraph.out_degree": 3.0,
            "source_entry": 123.0,
            "receiver.class_name_hash": 7.0,
            "safe.receiver_count": 2.0,
        }
    }
    assert safe_evidence_keys(evidence) == ["callgraph.out_degree", "safe.receiver_count"]


def test_accept_error_router_train_and_monotone_inference(tmp_path: Path) -> None:
    oof_path = tmp_path / "oof.jsonl"
    evidence_path = tmp_path / "evidence.jsonl"
    model_dir = tmp_path / "router"
    rows = make_oof()
    write_jsonl(oof_path, rows)
    write_jsonl(
        evidence_path,
        [
            {
                "format": EVIDENCE_FORMAT,
                "id": row["id"],
                "features": {
                    "callgraph.out_degree": 10.0 if row["correct"] else 1.0,
                    "source_entry": float(index),
                },
            }
            for index, row in enumerate(rows)
        ],
    )

    manifest = train_accept_error_router(
        oof_path,
        model_dir,
        evidence_path=evidence_path,
        seed=13,
        meta_folds=5,
        target_accept_precision=0.95,
        max_accept_coverage_loss=0.30,
        min_class_meta_examples=10,
        min_accept_examples=20,
    )
    assert manifest["format"] == FORMAT
    assert manifest["calibration"]["kept_precision"] >= 0.95
    assert manifest["calibration"]["kept_coverage"] >= 0.70
    assert "source_entry" not in manifest["evidence_keys"]
    validate_schema("accept-error-router-v1.schema.json", manifest)
    assert (model_dir / "accept_error_router.joblib").exists()
    assert (model_dir / "crossfit_accept_scores.jsonl").exists()
    for line in (model_dir / "crossfit_accept_scores.jsonl").read_text(encoding="utf-8").splitlines():
        validate_schema("accept-error-router-crossfit-score-v1.schema.json", json.loads(line))

    import joblib

    artifact = joblib.load(model_dir / "accept_error_router.joblib")
    evidence = load_evidence(evidence_path)
    inference_rows = [dict(row) for row in rows[:10]]
    inference_rows.append({
        "id": "preserve-review",
        "prediction": "alpha",
        "action": "review",
        "probabilities": {"alpha": 0.6, "beta": 0.4},
        "family_similarity": 0.2,
        "competing_similarity": 0.4,
        "contrast_margin": -0.2,
    })
    routed = route_rows(artifact, inference_rows, evidence=evidence)
    assert routed[-1]["base_action"] == "review"
    assert routed[-1]["action"] == "review"
    assert routed[-1]["accept_router_changed"] is False
    for row in routed:
        validate_schema("accept-error-router-prediction-v1.schema.json", row)
        if row["base_action"] != "accept":
            assert row["accept_error_router_reason"] == "base_action_preserved"
            assert row["accept_error_router_evidence_feature_count"] == 0
        elif row["action"] == "escalate":
            assert row["accept_error_router_reason"] == "accept_score_below_threshold"
            assert row["accept_error_router_evidence_feature_count"] == 1
        else:
            assert row["accept_error_router_reason"] == "accept_score_at_or_above_threshold"
            assert row["accept_error_router_evidence_feature_count"] == 1
    assert all(
        (row["base_action"], row["action"]) not in {
            ("review", "accept"), ("escalate", "accept"), ("escalate", "review")
        }
        for row in routed
    )
    assert any(row["accept_router_changed"] for row in routed[:-1])
    legacy_row = dict(routed[-1])
    legacy_row.pop("accept_error_router_reason")
    legacy_row.pop("accept_error_router_evidence_feature_count")
    validate_schema("accept-error-router-prediction-v1.schema.json", legacy_row)
    without_evidence = route_rows(artifact, inference_rows[:1], evidence={})
    assert without_evidence[0]["accept_error_router_evidence_feature_count"] == 0
