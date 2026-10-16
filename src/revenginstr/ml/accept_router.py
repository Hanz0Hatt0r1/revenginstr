"""Project-neutral cross-fitted accept-error router.

The router is trained only on held-out OOF rows that the base selective classifier
already marked ``accept``.  It learns the probability that the base prediction is
correct and may only demote an ``accept`` action; review/escalate rows are
preserved.  This is the reusable mechanism extracted from the Nevergone v9/v10
accept-error routing line.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any

from .evidence_tokens import load_evidence

FORMAT = "REVENGINSTR.AcceptErrorRouter/1"
BLOCKED_EVIDENCE_TERMS = (
    "label",
    "class_name",
    "classname",
    "vtable_id",
    "vtable_identity",
    "address",
    "source_entry",
    "function_name",
    "symbol_name",
)


def require_dependencies() -> dict[str, Any]:
    try:
        import joblib
        import numpy as np
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import StandardScaler
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("revenginstr accept routing requires the [ml] dependencies") from exc
    return {
        "joblib": joblib,
        "np": np,
        "LogisticRegression": LogisticRegression,
        "Pipeline": Pipeline,
        "StandardScaler": StandardScaler,
    }


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    with path.open("r", encoding="utf-8") as handle:
        for line_no, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            row = json.loads(raw)
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_no}: expected JSON object")
            record_id = row.get("id")
            if not isinstance(record_id, str) or not record_id:
                raise ValueError(f"{path}:{line_no}: missing id")
            if record_id in seen:
                raise ValueError(f"{path}:{line_no}: duplicate id {record_id}")
            seen.add(record_id)
            rows.append(row)
    return rows


def safe_evidence_keys(evidence: dict[str, dict[str, float]]) -> list[str]:
    keys: set[str] = set()
    for features in evidence.values():
        keys.update(str(key) for key in features)
    result = []
    for key in sorted(keys):
        lowered = key.lower()
        if any(term in lowered for term in BLOCKED_EVIDENCE_TERMS):
            continue
        result.append(key)
    return result


def _entropy(values: list[float]) -> float:
    total = 0.0
    for value in values:
        if value > 0.0:
            total -= value * math.log(value)
    return total


def feature_count(classes: list[str], evidence_keys: list[str]) -> int:
    return 2 * len(classes) + 6 + len(evidence_keys)


def build_matrix(
    rows: list[dict[str, Any]],
    evidence: dict[str, dict[str, float]],
    evidence_keys: list[str],
    classes: list[str],
    np,
):
    if not classes:
        raise ValueError("classes must not be empty")
    class_index = {label: index for index, label in enumerate(classes)}
    base_width = 2 * len(classes) + 6
    matrix = np.zeros((len(rows), base_width + len(evidence_keys)), dtype=np.float64)
    for row_index, row in enumerate(rows):
        probabilities = row.get("probabilities")
        if not isinstance(probabilities, dict):
            raise ValueError(f"row {row.get('id')}: probabilities object is required")
        probs = [float(probabilities.get(label, 0.0)) for label in classes]
        ordered = sorted(probs, reverse=True)
        matrix[row_index, 0 : len(classes)] = probs
        cursor = len(classes)
        matrix[row_index, cursor] = ordered[0] - ordered[1] if len(ordered) > 1 else ordered[0]
        matrix[row_index, cursor + 1] = _entropy(probs)
        matrix[row_index, cursor + 2] = max(probs)
        matrix[row_index, cursor + 3] = float(row.get("family_similarity", 0.0))
        matrix[row_index, cursor + 4] = float(row.get("competing_similarity", 0.0))
        matrix[row_index, cursor + 5] = float(row.get("contrast_margin", 0.0))
        one_hot = cursor + 6
        prediction = str(row.get("prediction", ""))
        if prediction not in class_index:
            raise ValueError(f"row {row.get('id')}: prediction {prediction!r} not in classes")
        matrix[row_index, one_hot + class_index[prediction]] = 1.0
        external = evidence.get(str(row["id"]), {})
        external_start = one_hot + len(classes)
        for offset, key in enumerate(evidence_keys):
            value = external.get(key, 0.0)
            if isinstance(value, (int, float)) and math.isfinite(float(value)):
                matrix[row_index, external_start + offset] = float(value)
    return matrix


def _make_meta_model(deps: dict[str, Any], seed: int):
    return deps["Pipeline"](
        [
            ("scale", deps["StandardScaler"]()),
            (
                "classifier",
                deps["LogisticRegression"](
                    class_weight="balanced",
                    max_iter=3000,
                    random_state=seed,
                    solver="liblinear",
                ),
            ),
        ]
    )


def _positive_probability(model, matrix, np):
    probabilities = model.predict_proba(matrix)
    classes = model.named_steps["classifier"].classes_.tolist()
    if 1 not in classes:
        return np.zeros(len(matrix), dtype=np.float64)
    return probabilities[:, classes.index(1)]


def fit_meta_models(
    matrix,
    predictions,
    targets,
    *,
    classes: list[str],
    seed: int,
    min_class_examples: int,
    deps: dict[str, Any],
):
    global_model = None
    if len(set(int(value) for value in targets.tolist())) == 2:
        global_model = _make_meta_model(deps, seed)
        global_model.fit(matrix, targets)

    class_models: dict[str, Any] = {}
    prediction_values = predictions.tolist()
    for class_offset, label in enumerate(classes):
        indices = [index for index, prediction in enumerate(prediction_values) if str(prediction) == label]
        if len(indices) < min_class_examples:
            continue
        class_targets = targets[indices]
        if len(set(int(value) for value in class_targets.tolist())) != 2:
            continue
        model = _make_meta_model(deps, seed + 100 + class_offset)
        model.fit(matrix[indices], class_targets)
        class_models[label] = model
    return global_model, class_models


def predict_meta_models(models, matrix, predictions, np):
    global_model, class_models = models
    if global_model is None and not class_models:
        return np.full(len(matrix), 0.5, dtype=np.float64)
    scores = np.full(len(matrix), 0.5, dtype=np.float64)
    if global_model is not None:
        scores[:] = _positive_probability(global_model, matrix, np)
    prediction_values = predictions.tolist()
    for label, model in class_models.items():
        indices = [index for index, prediction in enumerate(prediction_values) if str(prediction) == label]
        if indices:
            scores[indices] = _positive_probability(model, matrix[indices], np)
    return scores


def threshold_grid(scores, np) -> list[float]:
    values = {0.0, 1.0}
    for step in range(21):
        values.add(step / 20.0)
    if len(scores):
        for step in range(51):
            values.add(float(np.quantile(scores, step / 50.0)))
    return sorted(max(0.0, min(1.0, value)) for value in values)


def select_keep_threshold(
    scores,
    correct,
    *,
    total_rows: int,
    legacy_accept_count: int,
    target_precision: float,
    max_coverage_loss: float,
    min_accept_examples: int,
    np,
):
    base_coverage = legacy_accept_count / max(1, total_rows)
    candidates: list[dict[str, Any]] = []
    for threshold in threshold_grid(scores, np):
        keep = scores >= threshold
        examples = int(keep.sum())
        precision = float(correct[keep].mean()) if examples else 0.0
        coverage = examples / max(1, total_rows)
        eligible = bool(
            examples >= min_accept_examples
            and precision >= target_precision
            and coverage >= base_coverage - max_coverage_loss
        )
        candidates.append(
            {
                "threshold": float(threshold),
                "eligible": eligible,
                "examples": examples,
                "precision": precision,
                "coverage": coverage,
            }
        )
    eligible = [candidate for candidate in candidates if candidate["eligible"]]
    if not eligible:
        return None, candidates
    selected = max(
        eligible,
        key=lambda candidate: (
            candidate["coverage"],
            candidate["precision"],
            -candidate["threshold"],
        ),
    )
    return selected, candidates


def _infer_classes(rows: list[dict[str, Any]], requested: list[str] | None) -> list[str]:
    if requested:
        if len(set(requested)) != len(requested):
            raise ValueError("classes must be unique")
        return list(requested)
    values: set[str] = set()
    for row in rows:
        prediction = row.get("prediction")
        if isinstance(prediction, str) and prediction:
            values.add(prediction)
        probabilities = row.get("probabilities")
        if isinstance(probabilities, dict):
            values.update(str(label) for label in probabilities)
    if not values:
        raise ValueError("could not infer classes from OOF rows")
    return sorted(values)


def train_accept_router(
    oof_path: Path,
    output_dir: Path,
    *,
    evidence_path: Path | None = None,
    classes: list[str] | None = None,
    seed: int = 42,
    target_accept_precision: float = 0.97,
    max_accept_coverage_loss: float = 0.04,
    min_class_meta_examples: int = 100,
    min_accept_examples: int = 100,
    below_threshold_action: str = "escalate",
) -> dict[str, Any]:
    if not 0.0 <= target_accept_precision <= 1.0:
        raise ValueError("target_accept_precision must be in [0,1]")
    if not 0.0 <= max_accept_coverage_loss <= 1.0:
        raise ValueError("max_accept_coverage_loss must be in [0,1]")
    if below_threshold_action not in {"review", "escalate"}:
        raise ValueError("below_threshold_action must be review or escalate")

    deps = require_dependencies()
    np = deps["np"]
    rows = read_jsonl(oof_path)
    if not rows:
        raise ValueError("OOF file is empty")
    class_names = _infer_classes(rows, classes)
    evidence = load_evidence(evidence_path)
    evidence_keys = safe_evidence_keys(evidence)

    folds: list[int] = []
    correct_values: list[bool] = []
    legacy_actions: list[str] = []
    predictions: list[str] = []
    for row in rows:
        fold = row.get("fold")
        if not isinstance(fold, int) or fold <= 0:
            raise ValueError(
                f"row {row.get('id')}: positive integer fold is required; retrain the base classifier with a current revenginstr version"
            )
        prediction = str(row.get("prediction", ""))
        truth = str(row.get("truth", ""))
        if not prediction or not truth:
            raise ValueError(f"row {row.get('id')}: truth and prediction are required")
        folds.append(fold)
        correct_values.append(bool(row.get("correct", prediction == truth)))
        legacy_actions.append(str(row.get("action", "")))
        predictions.append(prediction)

    matrix = build_matrix(rows, evidence, evidence_keys, class_names, np)
    fold_array = np.asarray(folds, dtype=np.int64)
    correct = np.asarray(correct_values, dtype=bool)
    prediction_array = np.asarray(predictions, dtype=object)
    accept = np.asarray(
        [index for index, action in enumerate(legacy_actions) if action == "accept"],
        dtype=np.int64,
    )
    if len(accept) < min_accept_examples:
        raise ValueError(f"not enough legacy accept rows: {len(accept)} < {min_accept_examples}")
    unique_folds = sorted(set(fold_array[accept].tolist()))
    if len(unique_folds) < 2:
        raise ValueError("accept rows must span at least two OOF folds")

    crossfit_scores = np.full(len(accept), 0.5, dtype=np.float64)
    for fold in unique_folds:
        fit_local = np.where(fold_array[accept] != fold)[0]
        valid_local = np.where(fold_array[accept] == fold)[0]
        if not len(fit_local) or not len(valid_local):
            continue
        fit_global = accept[fit_local]
        valid_global = accept[valid_local]
        models = fit_meta_models(
            matrix[fit_global],
            prediction_array[fit_global],
            correct[fit_global].astype(np.int64),
            classes=class_names,
            seed=seed + 1000 + fold,
            min_class_examples=min_class_meta_examples,
            deps=deps,
        )
        crossfit_scores[valid_local] = predict_meta_models(
            models, matrix[valid_global], prediction_array[valid_global], np
        )

    selected, candidates = select_keep_threshold(
        crossfit_scores,
        correct[accept],
        total_rows=len(rows),
        legacy_accept_count=len(accept),
        target_precision=target_accept_precision,
        max_coverage_loss=max_accept_coverage_loss,
        min_accept_examples=min_accept_examples,
        np=np,
    )
    if selected is None:
        raise RuntimeError("no feasible threshold on cross-fitted accept correctness scores")
    threshold = float(selected["threshold"])
    keep = crossfit_scores >= threshold
    kept_examples = int(keep.sum())
    kept_precision = float(correct[accept][keep].mean()) if kept_examples else 0.0
    kept_coverage = kept_examples / len(rows)

    global_model, class_models = fit_meta_models(
        matrix[accept],
        prediction_array[accept],
        correct[accept].astype(np.int64),
        classes=class_names,
        seed=seed + 1_000_000,
        min_class_examples=min_class_meta_examples,
        deps=deps,
    )

    artifact = {
        "format": FORMAT,
        "threshold": threshold,
        "classes": class_names,
        "evidence_keys": evidence_keys,
        "meta_feature_count": feature_count(class_names, evidence_keys),
        "global_model": global_model,
        "class_models": class_models,
        "policy": {
            "scope": "legacy_accept_only",
            "below_threshold_action": below_threshold_action,
            "non_accept_action": "preserve",
            "promotions_allowed": False,
        },
        "calibration": {
            "method": "oof-fold-crossfit",
            "training_feedback": False,
            "target_accept_precision": target_accept_precision,
            "max_accept_coverage_loss": max_accept_coverage_loss,
            "legacy_accept_examples": int(len(accept)),
            "kept_examples": kept_examples,
            "kept_precision": kept_precision,
            "kept_coverage": kept_coverage,
            "candidate_count": len(candidates),
            "folds": unique_folds,
        },
        "leakage_policy": {
            "truth_used_as_model_feature": False,
            "function_names_used": False,
            "addresses_used": False,
            "raw_receiver_class_names_used": False,
            "raw_vtable_identities_used": False,
            "blocked_evidence_terms": list(BLOCKED_EVIDENCE_TERMS),
        },
    }

    output_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = output_dir / "accept_error_router.joblib"
    manifest_path = output_dir / "manifest.json"
    deps["joblib"].dump(artifact, artifact_path)
    manifest = {
        "format": FORMAT,
        "threshold": threshold,
        "classes": class_names,
        "evidence_feature_count": len(evidence_keys),
        "meta_feature_count": artifact["meta_feature_count"],
        "policy": artifact["policy"],
        "calibration": artifact["calibration"],
        "leakage_policy": artifact["leakage_policy"],
        "artifact": str(artifact_path),
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def apply_accept_router(
    router: dict[str, Any],
    rows: list[dict[str, Any]],
    *,
    evidence: dict[str, dict[str, float]] | None = None,
) -> list[dict[str, Any]]:
    if router.get("format") != FORMAT:
        raise ValueError(f"unsupported router format: {router.get('format')!r}")
    deps = require_dependencies()
    np = deps["np"]
    evidence = evidence or {}
    classes = list(router["classes"])
    evidence_keys = list(router.get("evidence_keys", []))
    matrix = build_matrix(rows, evidence, evidence_keys, classes, np)
    predictions = np.asarray([str(row.get("prediction", "")) for row in rows], dtype=object)
    scores = predict_meta_models(
        (router.get("global_model"), dict(router.get("class_models", {}))),
        matrix,
        predictions,
        np,
    )
    threshold = float(router["threshold"])
    demoted_action = str(router["policy"]["below_threshold_action"])

    output: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        payload = dict(row)
        base_action = str(row.get("action", ""))
        action = base_action
        score: float | None = None
        if base_action == "accept":
            score = float(scores[index])
            if score < threshold:
                action = demoted_action
        payload.update(
            {
                "base_action": base_action,
                "action": action,
                "accept_router_format": FORMAT,
                "accept_router_threshold": threshold,
                "accept_correctness_probability": score,
                "accept_router_changed": action != base_action,
            }
        )
        output.append(payload)
    return output


def train_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train REVENGINSTR.AcceptErrorRouter/1")
    parser.add_argument("oof_predictions", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--classes", nargs="+")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--target-accept-precision", type=float, default=0.97)
    parser.add_argument("--max-accept-coverage-loss", type=float, default=0.04)
    parser.add_argument("--min-class-meta-examples", type=int, default=100)
    parser.add_argument("--min-accept-examples", type=int, default=100)
    parser.add_argument("--below-threshold-action", choices=["review", "escalate"], default="escalate")
    args = parser.parse_args(argv)
    manifest = train_accept_router(
        args.oof_predictions,
        args.output_dir,
        evidence_path=args.evidence,
        classes=args.classes,
        seed=args.seed,
        target_accept_precision=args.target_accept_precision,
        max_accept_coverage_loss=args.max_accept_coverage_loss,
        min_class_meta_examples=args.min_class_meta_examples,
        min_accept_examples=args.min_accept_examples,
        below_threshold_action=args.below_threshold_action,
    )
    calibration = manifest["calibration"]
    print("format:", manifest["format"])
    print("threshold:", manifest["threshold"])
    print("crossfit accept precision:", f"{calibration['kept_precision']:.6f}")
    print("crossfit accept coverage:", f"{calibration['kept_coverage']:.6f}")
    print("accept rows:", calibration["legacy_accept_examples"])
    print("evidence features:", manifest["evidence_feature_count"])
    print("artifact:", manifest["artifact"])
    return 0


def apply_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Apply REVENGINSTR.AcceptErrorRouter/1")
    parser.add_argument("router_dir", type=Path)
    parser.add_argument("classified", type=Path)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    deps = require_dependencies()
    router = deps["joblib"].load(args.router_dir / "accept_error_router.joblib")
    rows = read_jsonl(args.classified)
    external = load_evidence(args.evidence)
    routed = apply_accept_router(router, rows, evidence=external)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in routed),
        encoding="utf-8",
    )
    changed = sum(bool(row.get("accept_router_changed")) for row in routed)
    accept = sum(row.get("action") == "accept" for row in routed)
    print("format:", FORMAT)
    print("rows:", len(routed))
    print("accept:", accept)
    print("changed accepts:", changed)
    print("output:", args.output)
    return 0
