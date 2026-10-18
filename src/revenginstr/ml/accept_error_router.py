"""Project-neutral accept-only correctness router.

The router is trained from already family-held-out base-classifier OOF rows. It
never changes semantic class predictions and never promotes an action. Only a
legacy ``accept`` may be downgraded to ``escalate`` when a second-stage
correctness model assigns a score below a cross-fitted production threshold.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import Counter
from pathlib import Path
from typing import Any

from .evidence_tokens import load_evidence
from .selective import require_dependencies

FORMAT = "REVENGINSTR.AcceptErrorRouter/1"
BLOCKED_EVIDENCE_TERMS = (
    "label", "class_name", "classname", "vtable_id", "vtable_identity",
    "address", "source_entry", "function_name", "symbol_name",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def identity_sha256(values: list[str]) -> str:
    payload = "".join(f"{value}\n" for value in sorted(set(values)))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    seen: set[str] = set()
    with path.open("r", encoding="utf-8") as handle:
        for line_no, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            row = json.loads(raw)
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_no}: expected object")
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
        for key in features:
            lowered = key.lower()
            if any(term in lowered for term in BLOCKED_EVIDENCE_TERMS):
                continue
            keys.add(key)
    return sorted(keys)


def _entropy(values: list[float]) -> float:
    return -sum(value * math.log(value) for value in values if value > 0.0)


def infer_classes(rows: list[dict[str, Any]]) -> list[str]:
    classes: set[str] = set()
    for row in rows:
        prediction = row.get("prediction")
        if isinstance(prediction, str) and prediction:
            classes.add(prediction)
        probabilities = row.get("probabilities")
        if isinstance(probabilities, dict):
            classes.update(str(key) for key in probabilities if isinstance(key, str) and key)
    if len(classes) < 2:
        raise ValueError("OOF rows must contain at least two classes")
    return sorted(classes)


def validate_oof_rows(rows: list[dict[str, Any]]) -> None:
    required = ("id", "family_id", "truth", "prediction", "action", "probabilities")
    for index, row in enumerate(rows, 1):
        missing = [key for key in required if key not in row]
        if missing:
            raise ValueError(f"OOF row {index} missing fields: {missing}")
        if not isinstance(row["family_id"], str) or not row["family_id"]:
            raise ValueError(f"OOF row {index} missing family_id")
        if row["action"] not in {"accept", "review", "escalate"}:
            raise ValueError(f"OOF row {index} has invalid action: {row['action']!r}")
        if not isinstance(row["probabilities"], dict):
            raise ValueError(f"OOF row {index} probabilities must be an object")


def build_matrix(rows: list[dict[str, Any]], classes: list[str],
                 evidence: dict[str, dict[str, float]], evidence_keys: list[str], np):
    # per-class probabilities + top gap/entropy/max + 3 family/OOD scalars +
    # predicted-class one-hot + sanitized external evidence.
    base_features = 2 * len(classes) + 6
    matrix = np.zeros((len(rows), base_features + len(evidence_keys)), dtype=np.float64)
    class_index = {label: index for index, label in enumerate(classes)}
    one_hot_start = len(classes) + 6
    for row_index, row in enumerate(rows):
        probs_map = row.get("probabilities", {})
        probs = [float(probs_map.get(label, 0.0)) for label in classes]
        ordered = sorted(probs, reverse=True)
        matrix[row_index, :len(classes)] = probs
        scalar = len(classes)
        matrix[row_index, scalar] = ordered[0] - ordered[1] if len(ordered) > 1 else ordered[0]
        matrix[row_index, scalar + 1] = _entropy(probs)
        matrix[row_index, scalar + 2] = max(probs) if probs else 0.0
        matrix[row_index, scalar + 3] = float(row.get("family_similarity", 0.0) or 0.0)
        matrix[row_index, scalar + 4] = float(row.get("competing_similarity", 0.0) or 0.0)
        matrix[row_index, scalar + 5] = float(row.get("contrast_margin", 0.0) or 0.0)
        prediction = str(row.get("prediction", ""))
        if prediction in class_index:
            matrix[row_index, one_hot_start + class_index[prediction]] = 1.0
        features = evidence.get(str(row["id"]), {})
        for offset, key in enumerate(evidence_keys, base_features):
            value = features.get(key, 0.0)
            if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(float(value)):
                matrix[row_index, offset] = float(value)
            elif isinstance(value, bool):
                matrix[row_index, offset] = float(value)
    return matrix


def make_meta_model(seed: int):
    try:
        from sklearn.linear_model import LogisticRegression
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import StandardScaler
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("scikit-learn is required for accept-error routing") from exc
    return Pipeline([
        ("scale", StandardScaler()),
        ("classifier", LogisticRegression(
            class_weight="balanced", max_iter=3000, random_state=seed, solver="liblinear"
        )),
    ])


def _positive_probability(model, matrix, np):
    raw = model.predict_proba(matrix)
    classes = model.named_steps["classifier"].classes_.tolist()
    if 1 not in classes:
        return np.zeros(len(matrix), dtype=np.float64)
    return raw[:, classes.index(1)]


def fit_meta_models(matrix, predictions, targets, classes: list[str], *,
                    seed: int, min_class_examples: int):
    global_model = None
    if len(set(int(value) for value in targets.tolist())) == 2:
        global_model = make_meta_model(seed)
        global_model.fit(matrix, targets)
    class_models: dict[str, Any] = {}
    for class_offset, label in enumerate(classes):
        indices = [index for index, prediction in enumerate(predictions.tolist()) if str(prediction) == label]
        if len(indices) < min_class_examples:
            continue
        class_targets = targets[indices]
        if len(set(int(value) for value in class_targets.tolist())) != 2:
            continue
        model = make_meta_model(seed + 100 + class_offset)
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
    for label, model in class_models.items():
        indices = [index for index, prediction in enumerate(predictions.tolist()) if str(prediction) == label]
        if indices:
            scores[indices] = _positive_probability(model, matrix[indices], np)
    return scores


def _safe_meta_folds(targets, groups, requested: int) -> int:
    counts = Counter(int(value) for value in targets.tolist())
    if len(counts) < 2:
        return 0
    maximum = min(requested, len(set(groups.tolist())), min(counts.values()))
    return maximum if maximum >= 2 else 0


def threshold_grid(scores, np) -> list[float]:
    values = {step / 20.0 for step in range(21)}
    values.update({0.0, 1.0})
    if len(scores):
        for step in range(51):
            values.add(float(np.quantile(scores, step / 50.0)))
    return sorted(max(0.0, min(1.0, value)) for value in values)


def select_keep_threshold(scores, correct, *, total_rows: int, legacy_accept_count: int,
                          target_precision: float, max_coverage_loss: float,
                          min_accept_examples: int, np):
    reports: list[dict[str, Any]] = []
    base_coverage = legacy_accept_count / max(1, total_rows)
    for threshold in threshold_grid(scores, np):
        keep = scores >= threshold
        count = int(keep.sum())
        precision = float(correct[keep].mean()) if count else 0.0
        coverage = count / max(1, total_rows)
        eligible = bool(
            count >= min_accept_examples
            and precision >= target_precision
            and coverage >= base_coverage - max_coverage_loss
        )
        reports.append({
            "threshold": float(threshold), "eligible": eligible,
            "examples": count, "precision": precision, "coverage": coverage,
        })
    eligible = [row for row in reports if row["eligible"]]
    if not eligible:
        return None, reports
    return max(
        eligible,
        key=lambda row: (row["coverage"], row["precision"], -row["threshold"]),
    ), reports


def train_accept_error_router(base_oof: Path, output_dir: Path, *, evidence_path: Path | None,
                              seed: int = 42, meta_folds: int = 5,
                              target_accept_precision: float = 0.97,
                              max_accept_coverage_loss: float = 0.04,
                              min_class_meta_examples: int = 100,
                              min_accept_examples: int = 100) -> dict[str, Any]:
    if not 0.0 < target_accept_precision <= 1.0:
        raise ValueError("target_accept_precision must be in (0, 1]")
    if not 0.0 <= max_accept_coverage_loss <= 1.0:
        raise ValueError("max_accept_coverage_loss must be in [0, 1]")
    deps = require_dependencies()
    np = deps["np"]
    rows = read_jsonl(base_oof)
    validate_oof_rows(rows)
    classes = infer_classes(rows)
    evidence = load_evidence(evidence_path)
    evidence_keys = safe_evidence_keys(evidence)
    matrix = build_matrix(rows, classes, evidence, evidence_keys, np)
    predictions = np.asarray([str(row["prediction"]) for row in rows], dtype=object)
    correct = np.asarray([
        bool(row.get("correct", str(row["prediction"]) == str(row["truth"]))) for row in rows
    ], dtype=bool)
    groups = np.asarray([str(row["family_id"]) for row in rows], dtype=object)
    accept = np.asarray([index for index, row in enumerate(rows) if row["action"] == "accept"], dtype=np.int64)
    if len(accept) < min_accept_examples:
        raise ValueError("not enough legacy accept rows")

    accept_targets = correct[accept].astype(np.int64)
    accept_groups = groups[accept]
    folds = _safe_meta_folds(accept_targets, accept_groups, meta_folds)
    if folds < 2:
        raise ValueError("not enough family-grouped correct/error ACCEPT examples for crossfit")

    splitter = deps["StratifiedGroupKFold"](n_splits=folds, shuffle=True, random_state=seed)
    crossfit_scores = np.full(len(accept), 0.5, dtype=np.float64)
    fold_reports: list[dict[str, Any]] = []
    for fold, (fit_local, valid_local) in enumerate(
        splitter.split(matrix[accept], accept_targets, accept_groups), 1
    ):
        fit_global = accept[fit_local]
        valid_global = accept[valid_local]
        models = fit_meta_models(
            matrix[fit_global], predictions[fit_global], correct[fit_global].astype(np.int64), classes,
            seed=seed + 1000 + fold, min_class_examples=min_class_meta_examples,
        )
        scores = predict_meta_models(models, matrix[valid_global], predictions[valid_global], np)
        crossfit_scores[valid_local] = scores
        fold_reports.append({
            "fold": fold, "fit_examples": int(len(fit_global)),
            "valid_examples": int(len(valid_global)),
            "valid_precision_at_0_5": float(correct[valid_global][scores >= 0.5].mean()) if int((scores >= 0.5).sum()) else 0.0,
        })

    selected, candidates = select_keep_threshold(
        crossfit_scores, correct[accept], total_rows=len(rows), legacy_accept_count=len(accept),
        target_precision=target_accept_precision,
        max_coverage_loss=max_accept_coverage_loss,
        min_accept_examples=min_accept_examples, np=np,
    )
    if selected is None:
        raise RuntimeError("no feasible production threshold on cross-fitted accept correctness scores")
    threshold = float(selected["threshold"])
    keep = crossfit_scores >= threshold
    kept_examples = int(keep.sum())
    kept_precision = float(correct[accept][keep].mean()) if kept_examples else 0.0
    kept_coverage = kept_examples / max(1, len(rows))

    final_models = fit_meta_models(
        matrix[accept], predictions[accept], correct[accept].astype(np.int64), classes,
        seed=seed + 1_000_000, min_class_examples=min_class_meta_examples,
    )
    artifact = {
        "format": FORMAT,
        "threshold": threshold,
        "classes": classes,
        "evidence_keys": evidence_keys,
        "base_feature_count": 2 * len(classes) + 6,
        "meta_feature_count": 2 * len(classes) + 6 + len(evidence_keys),
        "global_model": final_models[0],
        "class_models": final_models[1],
        "policy": {
            "scope": "base_accept_only",
            "below_threshold_action": "escalate",
            "non_accept_action": "preserve",
            "class_prediction_action": "preserve",
            "promotions_allowed": False,
        },
        "calibration": {
            "method": "family_grouped_crossfit_oof_accepts",
            "training_feedback": False,
            "folds": folds,
            "seed": seed,
            "target_accept_precision": target_accept_precision,
            "max_accept_coverage_loss": max_accept_coverage_loss,
            "legacy_accept_examples": int(len(accept)),
            "kept_examples": kept_examples,
            "kept_precision": kept_precision,
            "kept_coverage": kept_coverage,
            "candidate_count": len(candidates),
            "fold_reports": fold_reports,
        },
        "leakage_policy": {
            "family_grouped_crossfit": True,
            "raw_names_used": False,
            "addresses_used": False,
            "blocked_evidence_terms": list(BLOCKED_EVIDENCE_TERMS),
        },
        "source": {
            "base_oof_sha256": sha256_file(base_oof),
            "evidence_sha256": sha256_file(evidence_path) if evidence_path else None,
            "base_oof_rows": len(rows),
            "base_oof_id_sha256": identity_sha256([str(row["id"]) for row in rows]),
            "base_oof_family_sha256": identity_sha256([str(row["family_id"]) for row in rows]),
        },
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    deps["joblib"].dump(artifact, output_dir / "accept_error_router.joblib")
    manifest = {
        key: value for key, value in artifact.items()
        if key not in {"global_model", "class_models"}
    }
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with (output_dir / "crossfit_accept_scores.jsonl").open("w", encoding="utf-8") as handle:
        for local, global_index in enumerate(accept.tolist()):
            handle.write(json.dumps({
                "format": FORMAT,
                "id": rows[global_index]["id"],
                "family_id": rows[global_index]["family_id"],
                "prediction": rows[global_index]["prediction"],
                "truth": rows[global_index]["truth"],
                "correct": bool(correct[global_index]),
                "score": float(crossfit_scores[local]),
                "threshold": threshold,
                "keep": bool(keep[local]),
            }, sort_keys=True) + "\n")
    return manifest


def route_rows(artifact: dict[str, Any], base_rows: list[dict[str, Any]], *,
               evidence: dict[str, dict[str, float]] | None = None) -> list[dict[str, Any]]:
    if artifact.get("format") != FORMAT:
        raise ValueError(f"unsupported router format: {artifact.get('format')!r}")
    deps = require_dependencies()
    np = deps["np"]
    evidence = evidence or {}
    classes = list(artifact["classes"])
    evidence_keys = list(artifact.get("evidence_keys", []))
    matrix = build_matrix(base_rows, classes, evidence, evidence_keys, np)
    predictions = np.asarray([str(row.get("prediction", "")) for row in base_rows], dtype=object)
    accept_indices = np.asarray([index for index, row in enumerate(base_rows) if row.get("action") == "accept"], dtype=np.int64)
    scores = np.full(len(base_rows), np.nan, dtype=np.float64)
    if len(accept_indices):
        scores[accept_indices] = predict_meta_models(
            (artifact.get("global_model"), artifact.get("class_models", {})),
            matrix[accept_indices], predictions[accept_indices], np,
        )
    threshold = float(artifact["threshold"])
    routed: list[dict[str, Any]] = []
    for index, row in enumerate(base_rows):
        base_action = str(row.get("action", "escalate"))
        action = base_action
        score = None
        reason = "base_action_preserved"
        evidence_feature_count = 0
        if base_action == "accept":
            score = float(scores[index])
            features = evidence.get(str(row.get("id", "")), {})
            evidence_feature_count = sum(key in features for key in evidence_keys)
            if score < threshold:
                action = "escalate"
                reason = "accept_score_below_threshold"
            else:
                reason = "accept_score_at_or_above_threshold"
        output = dict(row)
        output.update({
            "accept_error_router_format": FORMAT,
            "base_action": base_action,
            "action": action,
            "accept_correctness_probability": score,
            "accept_router_changed": action != base_action,
            "accept_error_router_reason": reason,
            "accept_error_router_evidence_feature_count": evidence_feature_count,
        })
        routed.append(output)
    return routed


def train_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train REVENGINSTR.AcceptErrorRouter/1")
    parser.add_argument("base_oof", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--meta-folds", type=int, default=5)
    parser.add_argument("--target-accept-precision", type=float, default=0.97)
    parser.add_argument("--max-accept-coverage-loss", type=float, default=0.04)
    parser.add_argument("--min-class-meta-examples", type=int, default=100)
    parser.add_argument("--min-accept-examples", type=int, default=100)
    args = parser.parse_args(argv)
    manifest = train_accept_error_router(
        args.base_oof, args.output_dir, evidence_path=args.evidence,
        seed=args.seed, meta_folds=args.meta_folds,
        target_accept_precision=args.target_accept_precision,
        max_accept_coverage_loss=args.max_accept_coverage_loss,
        min_class_meta_examples=args.min_class_meta_examples,
        min_accept_examples=args.min_accept_examples,
    )
    calibration = manifest["calibration"]
    print("format:", FORMAT)
    print("threshold:", manifest["threshold"])
    print("crossfit accept precision:", f"{calibration['kept_precision']:.6f}")
    print("crossfit accept coverage:", f"{calibration['kept_coverage']:.6f}")
    print("legacy accept examples:", calibration["legacy_accept_examples"])
    print("kept examples:", calibration["kept_examples"])
    print("evidence features:", len(manifest["evidence_keys"]))
    print("artifact:", args.output_dir / "accept_error_router.joblib")
    return 0


def infer_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Apply REVENGINSTR.AcceptErrorRouter/1")
    parser.add_argument("router_dir", type=Path)
    parser.add_argument("base_predictions", type=Path)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    deps = require_dependencies()
    artifact = deps["joblib"].load(args.router_dir / "accept_error_router.joblib")
    base_rows = read_jsonl(args.base_predictions)
    routed = route_rows(artifact, base_rows, evidence=load_evidence(args.evidence))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in routed), encoding="utf-8")
    base_accept = sum(row.get("base_action") == "accept" for row in routed)
    kept_accept = sum(row.get("action") == "accept" for row in routed)
    changed = sum(bool(row.get("accept_router_changed")) for row in routed)
    promotions = sum(
        (row.get("base_action"), row.get("action")) in {
            ("review", "accept"), ("escalate", "accept"), ("escalate", "review")
        }
        for row in routed
    )
    print("format:", FORMAT)
    print("rows:", len(routed))
    print("base accepts:", base_accept)
    print("kept accepts:", kept_accept)
    print("changed actions:", changed)
    print("promotions:", promotions)
    print("output:", args.output)
    return 0
