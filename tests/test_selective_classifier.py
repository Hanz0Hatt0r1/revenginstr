from __future__ import annotations

import json
from pathlib import Path

from revenginstr.ml import SELECTIVE_CLASSIFIER_FORMAT
from revenginstr.ml.selective import (
    choose_precision_threshold,
    classify_rows,
    route_action_with_contrastive_ood,
    train_selective_classifier,
)


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def _text(label: str, variant: int) -> str:
    if label == "alpha":
        return (
            "ARCH=X8632\nENDIAN=LE\nPTR_SIZE=4\n"
            "o0 LOAD out=v0:4 addr=reg:4\n"
            f"o1 INT_ADD out=v1:4 in=v0:4 in=const:small:0x{4 + variant:x}:4\n"
            "o2 INT_AND out=v2:4 in=v1:4 in=const:small:0xff:4\n"
            "o3 RETURN ret=v2:4\n"
        )
    return (
        "ARCH=ARM32\nENDIAN=LE\nPTR_SIZE=4\n"
        "o0 LOAD out=v0:4 addr=reg:4\n"
        f"o1 INT_XOR out=v1:4 in=v0:4 in=const:small:0x{16 + variant:x}:4\n"
        "o2 STORE addr=reg:4 value=v1:4\n"
        "o3 RETURN ret=v1:4\n"
    )


def test_threshold_and_contrastive_routing() -> None:
    policy = choose_precision_threshold(
        [0.9, 0.8, 0.2], [True, True, False], target_precision=0.95, min_examples=1
    )
    assert policy is not None
    assert policy["examples"] == 2
    class_policies = {
        "alpha": {
            "accept_threshold": 0.8,
            "review_threshold": 0.5,
            "ood_accept_threshold": 0.7,
            "contrast_accept_threshold": 0.05,
        }
    }
    assert route_action_with_contrastive_ood("alpha", 0.9, 0.8, 0.1, class_policies) == "accept"
    assert route_action_with_contrastive_ood("alpha", 0.9, 0.6, 0.1, class_policies) == "review"
    assert route_action_with_contrastive_ood("alpha", 0.4, 0.9, 0.2, class_policies) == "escalate"


def test_train_serialize_and_infer_project_neutral_classifier(tmp_path: Path) -> None:
    dataset = tmp_path / "dataset"
    families_path = tmp_path / "families.jsonl"
    model_dir = tmp_path / "model"

    rows: list[dict] = []
    families: list[dict] = []
    for label in ("alpha", "beta"):
        for family_index in range(4):
            family_id = f"family-{label}-{family_index}"
            for member in range(2):
                record_id = f"{label}-{family_index}-{member}"
                rows.append({
                    "id": record_id,
                    "text": _text(label, family_index + member),
                    "labels": {"domain": label},
                })
                families.append({
                    "format": "REVENGINSTR.FunctionFamilies/1",
                    "id": record_id,
                    "family_id": family_id,
                    "family_size": 2,
                })

    _write_jsonl(dataset / "train.jsonl", rows[:8])
    _write_jsonl(dataset / "validation.jsonl", rows[8:12])
    _write_jsonl(dataset / "test.jsonl", rows[12:])
    _write_jsonl(families_path, families)

    manifest = train_selective_classifier(
        dataset,
        families_path,
        model_dir,
        task="domain",
        classes=["alpha", "beta"],
        folds=2,
        seed=7,
        accept_precision=0.8,
        review_precision=0.5,
        min_class_calibration_examples=2,
        min_class_threshold_examples=1,
        min_ood_threshold_examples=1,
    )
    assert manifest["format"] == SELECTIVE_CLASSIFIER_FORMAT
    assert manifest["functions"] == 16
    assert manifest["families"] == 8
    assert manifest["leakage_policy"]["function_names_used"] is False
    assert (model_dir / "classifier.joblib").exists()
    assert (model_dir / "oof_predictions.jsonl").exists()

    import joblib

    artifact = joblib.load(model_dir / "classifier.joblib")
    results = classify_rows(
        artifact,
        [
            {"id": "foreign-alpha", "model_text": _text("alpha", 1)},
            {"id": "foreign-beta", "model_text": _text("beta", 1)},
        ],
    )
    assert [row["prediction"] for row in results] == ["alpha", "beta"]
    assert all(row["format"] == SELECTIVE_CLASSIFIER_FORMAT for row in results)
    assert all(row["action"] in {"accept", "review", "escalate"} for row in results)
    assert all("family_similarity" in row and "contrast_margin" in row for row in results)
