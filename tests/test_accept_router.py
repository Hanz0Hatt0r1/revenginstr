from __future__ import annotations

import json
from pathlib import Path

import pytest

from revenginstr.ml.accept_router import (
    FORMAT,
    apply_accept_router,
    require_dependencies,
    safe_evidence_keys,
    train_accept_router,
)
from revenginstr.ml.evidence_tokens import EVIDENCE_FORMAT, load_evidence


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def _oof_rows() -> list[dict]:
    rows = []
    for index in range(120):
        truth = "game" if index % 2 == 0 else "engine"
        wrong = index % 10 in {0, 1}
        prediction = ("engine" if truth == "game" else "game") if wrong else truth
        strong = not wrong
        probability = 0.94 if strong else 0.56
        other = 1.0 - probability
        probs = {
            prediction: probability,
            ("engine" if prediction == "game" else "game"): other,
        }
        rows.append(
            {
                "id": f"sample:{index:04d}",
                "family_id": f"family-{index // 3:03d}",
                "truth": truth,
                "prediction": prediction,
                "correct": not wrong,
                "action": "accept" if index < 100 else ("review" if index < 110 else "escalate"),
                "probabilities": probs,
                "family_similarity": 0.88 if strong else 0.34,
                "competing_similarity": 0.22 if strong else 0.31,
                "contrast_margin": 0.66 if strong else 0.03,
            }
        )
    return rows


def test_safe_evidence_keys_blocks_identity_like_features() -> None:
    evidence = {
        "a": {
            "callgraph.out_degree": 2.0,
            "receiver.pointer_depth": 1.0,
            "source_entry_numeric": 1234.0,
            "vtable_identity_hash": 55.0,
            "symbol_name_length": 8.0,
        }
    }
    assert safe_evidence_keys(evidence) == ["callgraph.out_degree", "receiver.pointer_depth"]


def test_accept_router_trains_from_family_groups_and_is_monotone(tmp_path: Path) -> None:
    pytest.importorskip("sklearn")
    pytest.importorskip("joblib")
    oof = tmp_path / "oof.jsonl"
    evidence_path = tmp_path / "evidence.jsonl"
    model_dir = tmp_path / "router"
    _write_jsonl(oof, _oof_rows())
    _write_jsonl(
        evidence_path,
        [
            {
                "format": EVIDENCE_FORMAT,
                "id": f"sample:{index:04d}",
                "features": {
                    "callgraph.out_degree": float(index % 5),
                    "receiver.pointer_depth": float(index % 3),
                    "source_entry_numeric": float(index),
                },
            }
            for index in range(120)
        ],
    )

    manifest = train_accept_router(
        oof,
        model_dir,
        evidence_path=evidence_path,
        classes=["game", "engine"],
        meta_folds=4,
        target_accept_precision=0.95,
        max_accept_coverage_loss=0.25,
        min_class_meta_examples=8,
        min_accept_examples=20,
    )
    assert manifest["format"] == FORMAT
    assert manifest["calibration"]["fold_source"] == "derived_family_hash"
    assert manifest["calibration"]["kept_precision"] >= 0.95
    assert manifest["policy"]["promotions_allowed"] is False
    assert "source_entry_numeric" not in require_dependencies()["joblib"].load(
        model_dir / "accept_error_router.joblib"
    )["evidence_keys"]

    router = require_dependencies()["joblib"].load(model_dir / "accept_error_router.joblib")
    rows = _oof_rows()
    evidence = load_evidence(evidence_path)
    routed = apply_accept_router(router, rows, evidence=evidence)
    rank = {"escalate": 0, "review": 1, "accept": 2}
    assert len(routed) == len(rows)
    assert all(rank[row["action"]] <= rank[row["base_action"]] for row in routed)
    assert all(
        row["action"] == row["base_action"]
        for row in routed
        if row["base_action"] != "accept"
    )
    assert any(row["accept_router_changed"] for row in routed)


def test_accept_router_can_use_explicit_oof_folds(tmp_path: Path) -> None:
    pytest.importorskip("sklearn")
    pytest.importorskip("joblib")
    rows = _oof_rows()
    for index, row in enumerate(rows):
        row["fold"] = index % 5 + 1
    oof = tmp_path / "oof.jsonl"
    _write_jsonl(oof, rows)
    model_dir = tmp_path / "router"
    manifest = train_accept_router(
        oof,
        model_dir,
        classes=["game", "engine"],
        target_accept_precision=0.95,
        max_accept_coverage_loss=0.25,
        min_class_meta_examples=8,
        min_accept_examples=20,
    )
    assert manifest["calibration"]["fold_source"] == "explicit_oof_fold"
