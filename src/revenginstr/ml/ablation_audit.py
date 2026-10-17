"""Compare caller-provided family-grouped OOF classifier ablations."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import Counter
from pathlib import Path
from typing import Any

from revenginstr.ml import SELECTIVE_CLASSIFIER_FORMAT
from revenginstr.ml.evidence_selective import FORMAT as EVIDENCE_CLASSIFIER_FORMAT
from revenginstr.ml.selective import read_jsonl

FORMAT = "REVENGINSTR.ClassifierAblationAudit/1"
SET_FORMAT = "REVENGINSTR.ClassifierAblationSet/1"
CLASSIFIER_FORMATS = {SELECTIVE_CLASSIFIER_FORMAT, EVIDENCE_CLASSIFIER_FORMAT}
ROUTE_ACTIONS = {"accept", "review", "escalate"}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdefABCDEF" for character in value)
    )


def _load_manifest(manifest: Any, variant: str) -> tuple[list[str], str, str, int, int, int, int]:
    if not isinstance(manifest, dict):
        raise ValueError(f"variant {variant!r}: classifier manifest must be an object")
    format_name = manifest.get("format")
    classes = manifest.get("classes")
    task = manifest.get("task")
    calibration = manifest.get("calibration")
    functions, families = manifest.get("functions"), manifest.get("families")
    fingerprint = manifest.get("dataset_fingerprint_sha256")
    seed, folds = (calibration.get("seed") if isinstance(calibration, dict) else None), (
        calibration.get("folds") if isinstance(calibration, dict) else None
    )
    if (
        not isinstance(format_name, str)
        or format_name not in CLASSIFIER_FORMATS
        or not isinstance(classes, list)
        or len(classes) < 2
        or any(not isinstance(label, str) or not label for label in classes)
        or len(set(classes)) != len(classes)
        or not isinstance(task, str)
        or not task
        or not isinstance(calibration, dict)
        or calibration.get("source") != "family_grouped_oof"
        or isinstance(seed, bool)
        or not isinstance(seed, int)
        or isinstance(folds, bool)
        or not isinstance(folds, int)
        or folds < 2
        or isinstance(functions, bool)
        or not isinstance(functions, int)
        or functions < 1
        or isinstance(families, bool)
        or not isinstance(families, int)
        or families < 1
        or not _is_sha256(fingerprint)
    ):
        raise ValueError(f"variant {variant!r}: manifest is not a supported family-grouped OOF model")
    return classes, format_name, task, functions, families, seed, folds


def _validate_predictions(
    rows: list[dict[str, Any]], *, variant: str, classes: list[str], format_name: str,
    expected_rows: int, expected_families: int,
) -> tuple[dict[str, dict[str, Any]], set[str]]:
    if len(rows) != expected_rows:
        raise ValueError(f"variant {variant!r}: OOF row count disagrees with classifier manifest")
    allowed = set(classes)
    indexed: dict[str, dict[str, Any]] = {}
    families: set[str] = set()
    for line_no, row in enumerate(rows, 1):
        if not isinstance(row, dict) or row.get("format") != format_name:
            raise ValueError(f"variant {variant!r} row {line_no}: prediction format disagrees with manifest")
        record_id, family_id = row.get("id"), row.get("family_id")
        truth, prediction, correct = row.get("truth"), row.get("prediction"), row.get("correct")
        confidence, action = row.get("confidence"), row.get("action")
        if not isinstance(record_id, str) or not record_id or record_id in indexed:
            raise ValueError(f"variant {variant!r} row {line_no}: invalid or duplicate id")
        if not isinstance(family_id, str) or not family_id:
            raise ValueError(f"variant {variant!r} row {line_no}: invalid family_id")
        if not isinstance(truth, str) or truth not in allowed or not isinstance(prediction, str) or prediction not in allowed:
            raise ValueError(f"variant {variant!r} row {line_no}: truth or prediction outside classifier classes")
        if not isinstance(correct, bool) or correct != (truth == prediction):
            raise ValueError(f"variant {variant!r} row {line_no}: correct flag disagrees with labels")
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            raise ValueError(f"variant {variant!r} row {line_no}: invalid confidence")
        try:
            confidence = float(confidence)
        except OverflowError as exc:
            raise ValueError(f"variant {variant!r} row {line_no}: invalid confidence") from exc
        if not math.isfinite(confidence) or not 0.0 <= confidence <= 1.0:
            raise ValueError(f"variant {variant!r} row {line_no}: invalid confidence")
        if not isinstance(action, str) or action not in ROUTE_ACTIONS:
            raise ValueError(f"variant {variant!r} row {line_no}: invalid route action")
        indexed[record_id] = {
            "family_id": family_id,
            "truth": truth,
            "prediction": prediction,
            "correct": correct,
            "confidence": confidence,
            "action": action,
        }
        families.add(family_id)
    if len(families) != expected_families:
        raise ValueError(f"variant {variant!r}: OOF family count disagrees with classifier manifest")
    return indexed, families


def _metrics(rows: dict[str, dict[str, Any]], classes: list[str]) -> dict[str, Any]:
    counts = {
        label: {"support": 0, "predicted": 0, "true_positive": 0}
        for label in classes
    }
    correct_rows = 0
    for row in rows.values():
        counts[row["truth"]]["support"] += 1
        counts[row["prediction"]]["predicted"] += 1
        if row["correct"]:
            counts[row["truth"]]["true_positive"] += 1
            correct_rows += 1

    per_class = {}
    f1_values = []
    recalls = []
    for label in classes:
        count = counts[label]
        precision = count["true_positive"] / count["predicted"] if count["predicted"] else None
        recall = count["true_positive"] / count["support"] if count["support"] else None
        f1 = (
            2 * count["true_positive"] / (count["support"] + count["predicted"])
            if count["support"] + count["predicted"] else 0.0
        )
        f1_values.append(f1)
        if recall is not None:
            recalls.append(recall)
        per_class[label] = {**count, "precision": precision, "recall": recall, "f1": f1}

    action_counts = Counter(row["action"] for row in rows.values())
    accepted = [row for row in rows.values() if row["action"] == "accept"]
    return {
        "rows": len(rows),
        "correct_rows": correct_rows,
        "accuracy": correct_rows / len(rows),
        "balanced_accuracy": sum(recalls) / len(recalls) if recalls else None,
        "macro_f1": sum(f1_values) / len(f1_values),
        "per_class": per_class,
        "action_counts": {action: action_counts[action] for action in sorted(ROUTE_ACTIONS)},
        "accepted_rows": len(accepted),
        "accepted_precision": (
            sum(row["correct"] for row in accepted) / len(accepted) if accepted else None
        ),
        "accepted_coverage": len(accepted) / len(rows),
    }


def build_ablation_audit(
    ablation_set: dict[str, Any],
    manifests: dict[str, dict[str, Any]],
    predictions: dict[str, list[dict[str, Any]]],
    *,
    set_sha256: str,
    manifest_sha256: dict[str, str],
    predictions_sha256: dict[str, str],
) -> dict[str, Any]:
    if not isinstance(ablation_set, dict) or ablation_set.get("format") != SET_FORMAT:
        raise ValueError("unsupported classifier ablation set format")
    variants = ablation_set.get("variants")
    baseline = ablation_set.get("baseline")
    if (
        not isinstance(variants, dict) or len(variants) < 2
        or not isinstance(baseline, str) or baseline not in variants
        or any(not isinstance(name, str) or not name for name in variants)
    ):
        raise ValueError("ablation set must name a baseline and at least one comparison variant")
    if not _is_sha256(set_sha256):
        raise ValueError("ablation set SHA-256 is invalid")

    baseline_ids: set[str] | None = None
    baseline_rows: dict[str, dict[str, Any]] | None = None
    baseline_metrics: dict[str, Any] | None = None
    baseline_classes: list[str] | None = None
    baseline_task: str | None = None
    baseline_fingerprint: str | None = None
    baseline_seed: int | None = None
    baseline_folds: int | None = None
    results: dict[str, Any] = {}
    population_rows = 0
    population_families = 0

    for name in [baseline, *sorted(set(variants) - {baseline})]:
        if name not in manifests or name not in predictions:
            raise ValueError(f"variant {name!r}: missing manifest or prediction input")
        if not _is_sha256(manifest_sha256.get(name)) or not _is_sha256(predictions_sha256.get(name)):
            raise ValueError(f"variant {name!r}: input SHA-256 is invalid")
        manifest = manifests[name]
        classes, format_name, task, expected_rows, expected_families, seed, folds = _load_manifest(manifest, name)
        indexed, families = _validate_predictions(
            predictions[name], variant=name, classes=classes, format_name=format_name,
            expected_rows=expected_rows, expected_families=expected_families,
        )
        fingerprint = manifest["dataset_fingerprint_sha256"]
        if baseline_ids is None:
            baseline_ids = set(indexed)
            baseline_rows = indexed
            baseline_metrics = _metrics(indexed, classes)
            baseline_classes = classes
            baseline_task = task
            baseline_fingerprint = fingerprint
            baseline_seed, baseline_folds = seed, folds
            population_rows, population_families = len(indexed), len(families)
        elif (
            set(indexed) != baseline_ids
            or classes != baseline_classes
            or task != baseline_task
            or fingerprint != baseline_fingerprint
            or seed != baseline_seed
            or folds != baseline_folds
            or len(indexed) != population_rows
            or len(families) != population_families
        ):
            raise ValueError(f"variant {name!r}: OOF population differs from baseline")
        else:
            for record_id, row in indexed.items():
                reference = baseline_rows[record_id]
                if row["family_id"] != reference["family_id"] or row["truth"] != reference["truth"]:
                    raise ValueError(f"variant {name!r}: family or truth differs for a shared id")

        metrics = _metrics(indexed, classes)
        comparison = None
        if name != baseline:
            changed = fixed = introduced = 0
            for record_id, row in indexed.items():
                reference = baseline_rows[record_id]
                changed += row["prediction"] != reference["prediction"]
                fixed += not reference["correct"] and row["correct"]
                introduced += reference["correct"] and not row["correct"]
            comparison = {
                "changed_predictions": changed,
                "fixed_errors": fixed,
                "introduced_errors": introduced,
                "net_correct_change": metrics["correct_rows"] - baseline_metrics["correct_rows"],
                "accuracy_delta": metrics["accuracy"] - baseline_metrics["accuracy"],
                "balanced_accuracy_delta": (
                    metrics["balanced_accuracy"] - baseline_metrics["balanced_accuracy"]
                    if metrics["balanced_accuracy"] is not None and baseline_metrics["balanced_accuracy"] is not None
                    else None
                ),
                "macro_f1_delta": metrics["macro_f1"] - baseline_metrics["macro_f1"],
                "accepted_coverage_delta": metrics["accepted_coverage"] - baseline_metrics["accepted_coverage"],
                "accepted_precision_delta": (
                    metrics["accepted_precision"] - baseline_metrics["accepted_precision"]
                    if metrics["accepted_precision"] is not None and baseline_metrics["accepted_precision"] is not None
                    else None
                ),
            }
        results[name] = {
            "classifier_format": format_name,
            "manifest_sha256": manifest_sha256[name],
            "oof_predictions_sha256": predictions_sha256[name],
            "metrics": metrics,
            "comparison_to_baseline": comparison,
        }

    return {
        "format": FORMAT,
        "source": {
            "ablation_set_sha256": set_sha256,
            "baseline": baseline,
            "dataset_fingerprint_sha256": baseline_fingerprint,
            "oof_rows": population_rows,
            "oof_families": population_families,
            "family_grouped_oof": True,
        },
        "variants": results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ablation_set_json", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    set_bytes = args.ablation_set_json.read_bytes()
    ablation_set = json.loads(set_bytes)
    if not isinstance(ablation_set, dict) or not isinstance(ablation_set.get("variants"), dict):
        raise ValueError("ablation set must contain a variants object")
    base = args.ablation_set_json.resolve().parent
    manifests: dict[str, dict[str, Any]] = {}
    predictions: dict[str, list[dict[str, Any]]] = {}
    manifest_hashes: dict[str, str] = {}
    prediction_hashes: dict[str, str] = {}
    for name, inputs in ablation_set["variants"].items():
        if not isinstance(inputs, dict):
            raise ValueError(f"variant {name!r}: input references must be an object")
        required = {"manifest_path", "manifest_sha256", "oof_predictions_path", "oof_predictions_sha256"}
        if not required.issubset(inputs):
            raise ValueError(f"variant {name!r}: missing pinned input reference")
        if not _is_sha256(inputs["manifest_sha256"]) or not _is_sha256(inputs["oof_predictions_sha256"]):
            raise ValueError(f"variant {name!r}: input SHA-256 is invalid")
        if not isinstance(inputs["manifest_path"], str) or not isinstance(inputs["oof_predictions_path"], str):
            raise ValueError(f"variant {name!r}: input paths must be strings")
        manifest_path = Path(inputs["manifest_path"]).expanduser()
        prediction_path = Path(inputs["oof_predictions_path"]).expanduser()
        if not manifest_path.is_absolute():
            manifest_path = base / manifest_path
        if not prediction_path.is_absolute():
            prediction_path = base / prediction_path
        actual_manifest_sha = _sha256(manifest_path)
        actual_prediction_sha = _sha256(prediction_path)
        if actual_manifest_sha.lower() != inputs["manifest_sha256"].lower():
            raise ValueError(f"variant {name!r}: classifier manifest SHA-256 mismatch")
        if actual_prediction_sha.lower() != inputs["oof_predictions_sha256"].lower():
            raise ValueError(f"variant {name!r}: OOF prediction SHA-256 mismatch")
        manifests[name] = json.loads(manifest_path.read_text(encoding="utf-8"))
        predictions[name] = list(read_jsonl(prediction_path))
        manifest_hashes[name] = actual_manifest_sha
        prediction_hashes[name] = actual_prediction_sha

    result = build_ablation_audit(
        ablation_set, manifests, predictions,
        set_sha256=hashlib.sha256(set_bytes).hexdigest(),
        manifest_sha256=manifest_hashes,
        predictions_sha256=prediction_hashes,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("OOF rows:", result["source"]["oof_rows"])
    print("variants:", len(result["variants"]))
    print("output:", args.output)
    return 0
