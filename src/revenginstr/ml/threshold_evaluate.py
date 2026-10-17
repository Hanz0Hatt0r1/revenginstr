"""Evaluate OOF-selected thresholds and calibration on disjoint families."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
from typing import Any

from revenginstr.ml import SELECTIVE_CLASSIFIER_FORMAT
from revenginstr.ml.selective import read_jsonl
from revenginstr.ml.threshold_sweep import DEFAULT_TARGET_PRECISIONS, build_threshold_sweep

FORMAT = "REVENGINSTR.SelectiveThresholdEvaluation/1"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_evaluation_rows(
    rows: list[dict[str, Any]], classes: list[str], train_rows: list[dict[str, Any]]
) -> tuple[dict[str, list[dict[str, Any]]], set[str]]:
    if not rows:
        raise ValueError("family-held-out evaluation predictions must not be empty")
    allowed = set(classes)
    train_ids = {row["id"] for row in train_rows}
    train_families = {row["family_id"] for row in train_rows}
    seen_ids: set[str] = set()
    evaluation_families: set[str] = set()
    predicted = {label: [] for label in classes}
    for line_no, row in enumerate(rows, 1):
        if not isinstance(row, dict) or row.get("format") != SELECTIVE_CLASSIFIER_FORMAT:
            raise ValueError(f"evaluation row {line_no}: unsupported format")
        record_id, family_id = row.get("id"), row.get("family_id")
        truth, prediction = row.get("truth"), row.get("prediction")
        correct, confidence = row.get("correct"), row.get("confidence")
        if not isinstance(record_id, str) or not record_id or record_id in seen_ids or record_id in train_ids:
            raise ValueError(f"evaluation row {line_no}: invalid or overlapping id")
        if not isinstance(family_id, str) or not family_id:
            raise ValueError(f"evaluation row {line_no}: invalid family_id")
        if family_id in train_families:
            raise ValueError(f"evaluation row {line_no}: family overlaps OOF population")
        if (
            not isinstance(truth, str) or truth not in allowed
            or not isinstance(prediction, str) or prediction not in allowed
        ):
            raise ValueError(f"evaluation row {line_no}: truth or prediction outside manifest classes")
        if not isinstance(correct, bool) or correct != (truth == prediction):
            raise ValueError(f"evaluation row {line_no}: correct flag disagrees with truth and prediction")
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            raise ValueError(f"evaluation row {line_no}: invalid calibrated confidence")
        try:
            confidence = float(confidence)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError(f"evaluation row {line_no}: invalid calibrated confidence") from exc
        if not math.isfinite(confidence) or not 0.0 <= confidence <= 1.0:
            raise ValueError(f"evaluation row {line_no}: invalid calibrated confidence")
        seen_ids.add(record_id)
        evaluation_families.add(family_id)
        predicted[prediction].append({"correct": correct, "confidence": confidence})
    return predicted, evaluation_families


def _reliability(rows: list[dict[str, Any]], bin_count: int) -> dict[str, Any]:
    count = len(rows)
    bins = []
    for index in range(bin_count):
        lower, upper = index / bin_count, (index + 1) / bin_count
        values = [
            row for row in rows
            if lower <= row["confidence"] < upper
            or (index == bin_count - 1 and row["confidence"] == 1.0)
        ]
        bins.append({
            "lower_bound": lower,
            "upper_bound": upper,
            "count": len(values),
            "mean_confidence": sum(row["confidence"] for row in values) / len(values) if values else None,
            "observed_accuracy": sum(row["correct"] for row in values) / len(values) if values else None,
        })
    return {
        "sample_count": count,
        "brier_score": (
            sum((row["confidence"] - float(row["correct"])) ** 2 for row in rows) / count
            if count else None
        ),
        "expected_calibration_error": (
            sum(
                item["count"] * abs(item["mean_confidence"] - item["observed_accuracy"])
                for item in bins if item["count"]
            ) / count if count else None
        ),
        "bins": bins,
    }


def build_threshold_evaluation(
    manifest: dict[str, Any],
    oof_rows: list[dict[str, Any]],
    evaluation_rows: list[dict[str, Any]],
    *,
    targets: list[float],
    min_train_examples: int,
    bin_count: int,
    manifest_sha256: str,
    oof_sha256: str,
    evaluation_sha256: str,
) -> dict[str, Any]:
    if not 1 <= bin_count <= 1000:
        raise ValueError("bin_count must be in [1, 1000]")
    training_sweep = build_threshold_sweep(
        manifest, oof_rows, targets=targets, min_examples=min_train_examples,
        manifest_sha256=manifest_sha256, predictions_sha256=oof_sha256,
    )
    classes = manifest["classes"]
    predicted, evaluation_families = _validate_evaluation_rows(evaluation_rows, classes, oof_rows)
    class_results = {}
    for label in sorted(classes):
        rows = predicted[label]
        calibration = _reliability(rows, bin_count)
        thresholds = []
        training_results = {
            item["target_precision"]: item
            for item in training_sweep["classes"][label]["sweeps"]
        }
        for target in training_sweep["targets"]:
            training = training_results[target]
            threshold = training["threshold"]
            if training["status"] != "feasible":
                status = "unavailable"
                accepted_rows = []
            elif not rows:
                status = "no_predictions"
                accepted_rows = []
            else:
                status = "measured"
                accepted_rows = [row for row in rows if row["confidence"] >= threshold]
            accepted = len(accepted_rows)
            thresholds.append({
                "target_precision": target,
                "training_status": training["status"],
                "training_threshold": threshold,
                "training_precision": training["precision"],
                "training_coverage": training["coverage"],
                "evaluation_status": status,
                "accepted_examples": accepted,
                "precision": (
                    sum(row["correct"] for row in accepted_rows) / accepted if accepted else None
                ),
                "coverage": accepted / len(rows) if rows else 0.0,
            })
        class_results[label] = {
            "evaluation_predictions": len(rows),
            "correct_predictions": sum(row["correct"] for row in rows),
            "accuracy": sum(row["correct"] for row in rows) / len(rows) if rows else None,
            "calibration": calibration,
            "thresholds": thresholds,
        }
    return {
        "format": FORMAT,
        "source": {
            "classifier_format": SELECTIVE_CLASSIFIER_FORMAT,
            "manifest_sha256": manifest_sha256,
            "oof_predictions_sha256": oof_sha256,
            "evaluation_predictions_sha256": evaluation_sha256,
            "training_oof_rows": len(oof_rows),
            "training_oof_families": len({row["family_id"] for row in oof_rows}),
            "evaluation_rows": len(evaluation_rows),
            "evaluation_families": len(evaluation_families),
            "family_disjoint": True,
        },
        "min_train_examples": min_train_examples,
        "bin_count": bin_count,
        "targets": training_sweep["targets"],
        "classes": class_results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("classifier_manifest", type=Path)
    parser.add_argument("oof_predictions_jsonl", type=Path)
    parser.add_argument("evaluation_predictions_jsonl", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target-precision", type=float, action="append", dest="targets")
    parser.add_argument("--min-train-examples", type=int, default=10)
    parser.add_argument("--bins", type=int, default=10)
    args = parser.parse_args(argv)

    manifest_bytes = args.classifier_manifest.read_bytes()
    manifest = json.loads(manifest_bytes)
    oof_rows = list(read_jsonl(args.oof_predictions_jsonl))
    evaluation_rows = list(read_jsonl(args.evaluation_predictions_jsonl))
    targets = args.targets if args.targets is not None else list(DEFAULT_TARGET_PRECISIONS)
    result = build_threshold_evaluation(
        manifest, oof_rows, evaluation_rows,
        targets=targets,
        min_train_examples=args.min_train_examples,
        bin_count=args.bins,
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        oof_sha256=_sha256(args.oof_predictions_jsonl),
        evaluation_sha256=_sha256(args.evaluation_predictions_jsonl),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("training OOF rows:", result["source"]["training_oof_rows"])
    print("evaluation rows:", result["source"]["evaluation_rows"])
    print("family-disjoint:", result["source"]["family_disjoint"])
    print("classes:", len(result["classes"]))
    print("output:", args.output)
    return 0
