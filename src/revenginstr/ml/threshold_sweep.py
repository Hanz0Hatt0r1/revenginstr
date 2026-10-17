"""Audit per-class selective thresholds on family-grouped OOF predictions."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import Counter
from pathlib import Path
from typing import Any

from revenginstr.ml import SELECTIVE_CLASSIFIER_FORMAT
from revenginstr.ml.selective import choose_precision_threshold, read_jsonl

FORMAT = "REVENGINSTR.SelectiveThresholdSweep/1"
DEFAULT_TARGET_PRECISIONS = (0.85, 0.90, 0.95, 0.97)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_threshold_sweep(
    manifest: dict[str, Any],
    rows: list[dict[str, Any]],
    *,
    targets: list[float],
    min_examples: int,
    manifest_sha256: str,
    predictions_sha256: str,
) -> dict[str, Any]:
    """Summarize per-class confidence thresholds without changing routing policy."""
    if not isinstance(manifest, dict):
        raise ValueError("classifier manifest must be an object")
    if manifest.get("format") != SELECTIVE_CLASSIFIER_FORMAT:
        raise ValueError("unsupported classifier manifest format")
    calibration = manifest.get("calibration")
    if not isinstance(calibration, dict) or calibration.get("source") != "family_grouped_oof":
        raise ValueError("threshold sweep requires family-grouped OOF calibration")
    classes = manifest.get("classes")
    if (
        not isinstance(classes, list)
        or len(classes) < 2
        or any(not isinstance(label, str) or not label for label in classes)
        or len(set(classes)) != len(classes)
    ):
        raise ValueError("classifier manifest has invalid classes")
    if not rows:
        raise ValueError("OOF predictions must not be empty")
    if not targets:
        raise ValueError("target precisions must be finite and in (0, 1]")
    normalized_targets = []
    for value in targets:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError("target precisions must be finite and in (0, 1]")
        try:
            target = float(value)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError("target precisions must be finite and in (0, 1]") from exc
        if isinstance(value, bool) or not math.isfinite(target) or not 0.0 < target <= 1.0:
            raise ValueError("target precisions must be finite and in (0, 1]")
        normalized_targets.append(target)
    targets = normalized_targets
    if len(set(targets)) != len(targets):
        raise ValueError("target precisions must be unique")
    if min_examples < 1:
        raise ValueError("min_examples must be positive")

    allowed = set(classes)
    seen_ids: set[str] = set()
    families: set[str] = set()
    truth_counts: Counter[str] = Counter()
    predicted: dict[str, list[dict[str, Any]]] = {label: [] for label in classes}
    for line_no, row in enumerate(rows, 1):
        if not isinstance(row, dict):
            raise ValueError(f"OOF row {line_no}: expected object")
        if row.get("format") != SELECTIVE_CLASSIFIER_FORMAT:
            raise ValueError(f"OOF row {line_no}: unsupported format")
        record_id = row.get("id")
        family_id = row.get("family_id")
        truth = row.get("truth")
        prediction = row.get("prediction")
        correct = row.get("correct")
        confidence = row.get("confidence")
        if not isinstance(record_id, str) or not record_id or record_id in seen_ids:
            raise ValueError(f"OOF row {line_no}: invalid or duplicate id")
        if not isinstance(family_id, str) or not family_id:
            raise ValueError(f"OOF row {line_no}: invalid family_id")
        if (
            not isinstance(truth, str) or truth not in allowed
            or not isinstance(prediction, str) or prediction not in allowed
        ):
            raise ValueError(f"OOF row {line_no}: truth or prediction outside manifest classes")
        if not isinstance(correct, bool) or correct != (truth == prediction):
            raise ValueError(f"OOF row {line_no}: correct flag disagrees with truth and prediction")
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            raise ValueError(f"OOF row {line_no}: invalid calibrated confidence")
        try:
            numeric_confidence = float(confidence)
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError(f"OOF row {line_no}: invalid calibrated confidence") from exc
        if isinstance(confidence, bool) or not math.isfinite(numeric_confidence) or not 0.0 <= numeric_confidence <= 1.0:
            raise ValueError(f"OOF row {line_no}: invalid calibrated confidence")
        seen_ids.add(record_id)
        families.add(family_id)
        truth_counts[truth] += 1
        predicted[prediction].append({"correct": correct, "confidence": numeric_confidence})

    function_count = manifest.get("functions")
    family_count = manifest.get("families")
    class_distribution = manifest.get("class_distribution")
    if (
        isinstance(function_count, bool) or not isinstance(function_count, int) or function_count < 1
        or isinstance(family_count, bool) or not isinstance(family_count, int) or family_count < 1
        or not isinstance(class_distribution, dict)
        or any(
            not isinstance(label, str) or label not in allowed
            or isinstance(count, bool) or not isinstance(count, int) or count < 0
            for label, count in class_distribution.items()
        )
    ):
        raise ValueError("classifier manifest has invalid population counts")
    if len(rows) != function_count:
        raise ValueError("OOF row count disagrees with classifier manifest")
    if len(families) != family_count:
        raise ValueError("OOF family count disagrees with classifier manifest")
    if dict(sorted(truth_counts.items())) != class_distribution:
        raise ValueError("OOF truth distribution disagrees with classifier manifest")

    sorted_targets = sorted(targets)
    class_results: dict[str, dict[str, Any]] = {}
    for label in sorted(classes):
        class_rows = predicted[label]
        correct = [row["correct"] for row in class_rows]
        confidences = [row["confidence"] for row in class_rows]
        count = len(class_rows)
        sweeps = []
        for target in sorted_targets:
            policy = choose_precision_threshold(
                confidences, correct, target_precision=target, min_examples=min_examples
            ) if count >= min_examples else None
            if policy is not None:
                status = "feasible"
                threshold = policy["threshold"]
                precision = policy["precision"]
                accepted = policy["examples"]
                coverage = policy["coverage"]
            else:
                status = "no_predictions" if count == 0 else (
                    "insufficient_examples" if count < min_examples else "target_unmet"
                )
                threshold = precision = None
                accepted = 0
                coverage = 0.0
            sweeps.append({
                "target_precision": target,
                "status": status,
                "threshold": threshold,
                "precision": precision,
                "accepted_examples": accepted,
                "coverage": coverage,
            })
        class_results[label] = {
            "predicted_examples": count,
            "correct_predictions": sum(correct),
            "baseline_precision": sum(correct) / count if count else None,
            "sweeps": sweeps,
        }

    return {
        "format": FORMAT,
        "source": {
            "classifier_format": SELECTIVE_CLASSIFIER_FORMAT,
            "manifest_sha256": manifest_sha256,
            "predictions_sha256": predictions_sha256,
            "prediction_rows": len(rows),
            "families": len(families),
        },
        "min_examples": min_examples,
        "targets": sorted_targets,
        "classes": class_results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("classifier_manifest", type=Path)
    parser.add_argument("oof_predictions_jsonl", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--target-precision", type=float, action="append", dest="targets")
    parser.add_argument("--min-examples", type=int, default=10)
    args = parser.parse_args(argv)

    manifest_bytes = args.classifier_manifest.read_bytes()
    manifest = json.loads(manifest_bytes)
    rows = list(read_jsonl(args.oof_predictions_jsonl))
    targets = args.targets if args.targets is not None else list(DEFAULT_TARGET_PRECISIONS)
    result = build_threshold_sweep(
        manifest,
        rows,
        targets=targets,
        min_examples=args.min_examples,
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        predictions_sha256=_sha256(args.oof_predictions_jsonl),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("prediction rows:", result["source"]["prediction_rows"])
    print("classes:", len(result["classes"]))
    print("target precision levels:", len(result["targets"]))
    print("output:", args.output)
    return 0
