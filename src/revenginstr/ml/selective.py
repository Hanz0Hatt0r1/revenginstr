"""Train and run a project-neutral selective portable-P-code classifier.

The model is intentionally simple and reproducible:
portable P-code -> TF-IDF uni/bi-grams -> balanced logistic regression.

Confidence calibration and routing thresholds are learned only from
family-grouped out-of-fold predictions. Automatic accept additionally requires
support from a label-pure training family and a non-negative contrast against the
strongest competing-class family.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, TextIO

from revenginstr.family.features import portable_pcode
from . import SELECTIVE_CLASSIFIER_FORMAT
from .similarity import build_family_prototypes, contrastive_family_scores


def require_dependencies() -> dict[str, Any]:
    try:
        import joblib
        import numpy as np
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.isotonic import IsotonicRegression
        from sklearn.linear_model import LogisticRegression
        from sklearn.metrics import accuracy_score, balanced_accuracy_score, f1_score
        from sklearn.model_selection import StratifiedGroupKFold
        from sklearn.pipeline import Pipeline
    except ImportError as exc:
        raise SystemExit(
            "Selective classifier requires numpy, scipy, scikit-learn and joblib. "
            "Install with: python -m pip install -e '.[ml]'"
        ) from exc
    return {
        "joblib": joblib,
        "np": np,
        "TfidfVectorizer": TfidfVectorizer,
        "IsotonicRegression": IsotonicRegression,
        "LogisticRegression": LogisticRegression,
        "accuracy_score": accuracy_score,
        "balanced_accuracy_score": balanced_accuracy_score,
        "f1_score": f1_score,
        "StratifiedGroupKFold": StratifiedGroupKFold,
        "Pipeline": Pipeline,
    }


def read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line_no, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            try:
                row = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_no}: expected object")
            yield row


def normalize_portable(text: str) -> str:
    normalized = portable_pcode(text)
    if normalized:
        return normalized
    lines = [line for line in text.splitlines() if line.startswith("OP ")]
    if lines:
        return "\n".join(lines)
    raise ValueError("input contains no portable P-code operations")


def load_family_map(path: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for row in read_jsonl(path):
        record_id, family_id = row.get("id"), row.get("family_id")
        if not isinstance(record_id, str) or not record_id:
            raise ValueError("family row missing id")
        if not isinstance(family_id, str) or not family_id:
            raise ValueError(f"family row {record_id} missing family_id")
        previous = result.get(record_id)
        if previous is not None and previous != family_id:
            raise ValueError(f"conflicting family IDs for {record_id}")
        result[record_id] = family_id
    return result


def load_dataset(dataset_dir: Path, families_path: Path, *, task: str, classes: list[str]) -> list[dict[str, str]]:
    family_map = load_family_map(families_path)
    allowed = set(classes)
    rows: list[dict[str, str]] = []
    seen: set[str] = set()
    for split in ("train", "validation", "test"):
        path = dataset_dir / f"{split}.jsonl"
        if not path.exists():
            continue
        for row in read_jsonl(path):
            record_id = row.get("id")
            if not isinstance(record_id, str) or not record_id:
                raise ValueError(f"{path}: row missing id")
            if record_id in seen:
                raise ValueError(f"duplicate dataset id: {record_id}")
            seen.add(record_id)
            labels = row.get("labels")
            if not isinstance(labels, dict):
                continue
            label = labels.get(task)
            if label not in allowed:
                continue
            text = row.get("text")
            if not isinstance(text, str) or not text:
                raise ValueError(f"dataset row {record_id} missing text")
            family_id = family_map.get(record_id)
            if family_id is None:
                raise ValueError(f"dataset id missing from family map: {record_id}")
            rows.append({
                "id": record_id,
                "text": normalize_portable(text),
                "label": str(label),
                "family_id": family_id,
            })
    if not rows:
        raise ValueError("no labelled rows selected")
    return rows


def make_model(deps: dict[str, Any], seed: int):
    return deps["Pipeline"]([
        ("tfidf", deps["TfidfVectorizer"](
            tokenizer=str.split,
            token_pattern=None,
            lowercase=False,
            ngram_range=(1, 2),
            min_df=2,
            max_features=80000,
            sublinear_tf=True,
        )),
        ("classifier", deps["LogisticRegression"](
            solver="lbfgs",
            max_iter=4000,
            class_weight="balanced",
            random_state=seed,
        )),
    ])


def choose_precision_threshold(confidences: list[float], correct: list[bool], *, target_precision: float, min_examples: int) -> dict[str, float | int] | None:
    if len(confidences) != len(correct):
        raise ValueError("confidence/correct length mismatch")
    if not 0.0 < target_precision <= 1.0:
        raise ValueError("target_precision must be in (0, 1]")
    if min_examples < 1:
        raise ValueError("min_examples must be positive")
    pairs = sorted(zip(confidences, correct), key=lambda item: item[0], reverse=True)
    best = None
    accepted = hits = index = 0
    total = len(pairs)
    while index < total:
        threshold = pairs[index][0]
        while index < total and math.isclose(pairs[index][0], threshold, rel_tol=0.0, abs_tol=1e-12):
            accepted += 1
            hits += int(bool(pairs[index][1]))
            index += 1
        if accepted < min_examples:
            continue
        precision = hits / accepted
        if precision + 1e-12 < target_precision:
            continue
        candidate = {
            "threshold": float(threshold),
            "precision": float(precision),
            "coverage": float(accepted / total) if total else 0.0,
            "examples": int(accepted),
        }
        if best is None or int(candidate["examples"]) > int(best["examples"]):
            best = candidate
    return best


def route_action(confidence: float, *, accept_threshold: float | None, review_threshold: float | None) -> str:
    if accept_threshold is not None and confidence >= float(accept_threshold):
        return "accept"
    if review_threshold is not None and confidence >= float(review_threshold):
        return "review"
    return "escalate"


def route_action_with_contrastive_ood(prediction: str, confidence: float, predicted_similarity: float, contrast_margin: float, class_policies: dict[str, dict[str, Any]]) -> str:
    policy = class_policies.get(prediction)
    if not isinstance(policy, dict):
        return "escalate"
    base = route_action(
        confidence,
        accept_threshold=policy.get("accept_threshold"),
        review_threshold=policy.get("review_threshold"),
    )
    if base != "accept":
        return base
    similarity_threshold = policy.get("ood_accept_threshold")
    margin_threshold = policy.get("contrast_accept_threshold")
    if (
        similarity_threshold is not None
        and margin_threshold is not None
        and predicted_similarity >= float(similarity_threshold)
        and contrast_margin >= float(margin_threshold)
    ):
        return "accept"
    review_threshold = policy.get("review_threshold")
    if review_threshold is not None and confidence >= float(review_threshold):
        return "review"
    return "escalate"


def calibrate_confidence(prediction: str, raw_confidence: float, *, global_calibrator, class_calibrators: dict[str, Any]) -> tuple[float, str]:
    calibrator = class_calibrators.get(prediction)
    source = "classwise"
    if calibrator is None:
        calibrator = global_calibrator
        source = "global_fallback"
    return float(calibrator.predict([raw_confidence])[0]), source


def fit_isotonic(deps: dict[str, Any], x, y, *, min_examples: int):
    if len(x) < min_examples or len({int(bool(value)) for value in y}) < 2:
        return None
    calibrator = deps["IsotonicRegression"](y_min=0.0, y_max=1.0, out_of_bounds="clip")
    calibrator.fit(x, y)
    return calibrator


def selective_summary(actions: list[str], correct, np) -> dict[str, dict[str, float | int]]:
    result: dict[str, dict[str, float | int]] = {}
    action_array = np.asarray(actions, dtype=object)
    total = len(actions)
    for action in ("accept", "review", "escalate"):
        mask = action_array == action
        count = int(mask.sum())
        result[action] = {
            "examples": count,
            "coverage": float(count / total) if total else 0.0,
            "precision": float(correct[mask].mean()) if count else 0.0,
        }
    return result


def sha256_rows(rows: list[dict[str, str]]) -> str:
    digest = hashlib.sha256()
    for row in sorted(rows, key=lambda item: item["id"]):
        for key in ("id", "label", "family_id", "text"):
            digest.update(row[key].encode("utf-8"))
            digest.update(b"\0")
        digest.update(b"\n")
    return digest.hexdigest()


def train_selective_classifier(dataset_dir: Path, families_path: Path, output_dir: Path, *, task: str, classes: list[str], folds: int = 5, seed: int = 42, accept_precision: float = 0.95, review_precision: float = 0.85, min_class_calibration_examples: int = 25, min_class_threshold_examples: int = 10, min_ood_threshold_examples: int = 10) -> dict[str, Any]:
    if folds < 2:
        raise ValueError("folds must be >= 2")
    if review_precision > accept_precision:
        raise ValueError("review_precision must be <= accept_precision")
    if len(classes) < 2 or len(set(classes)) != len(classes):
        raise ValueError("classes must contain at least two unique labels")

    deps = require_dependencies()
    np = deps["np"]
    rows = load_dataset(dataset_dir, families_path, task=task, classes=classes)
    texts = np.asarray([row["text"] for row in rows], dtype=object)
    labels = np.asarray([row["label"] for row in rows], dtype=object)
    groups = np.asarray([row["family_id"] for row in rows], dtype=object)
    missing = set(classes) - set(labels.tolist())
    if missing:
        raise ValueError(f"selected dataset missing classes: {sorted(missing)}")

    splitter = deps["StratifiedGroupKFold"](n_splits=folds, shuffle=True, random_state=seed)
    class_index = {label: index for index, label in enumerate(classes)}
    oof_pred = np.empty(len(rows), dtype=object)
    oof_raw = np.zeros(len(rows), dtype=np.float64)
    oof_probs = np.zeros((len(rows), len(classes)), dtype=np.float64)
    oof_pred_similarity = np.zeros(len(rows), dtype=np.float64)
    oof_competing_similarity = np.zeros(len(rows), dtype=np.float64)
    oof_margin = np.zeros(len(rows), dtype=np.float64)
    oof_pred_family = np.empty(len(rows), dtype=object)
    oof_competing_family = np.empty(len(rows), dtype=object)
    oof_competing_label = np.empty(len(rows), dtype=object)
    oof_pred_family[:] = None
    oof_competing_family[:] = None
    oof_competing_label[:] = None

    fold_metrics: list[dict[str, Any]] = []
    for fold, (train_idx, test_idx) in enumerate(splitter.split(texts, labels, groups), 1):
        model = make_model(deps, seed + fold)
        train_texts = texts[train_idx].tolist()
        train_labels = labels[train_idx].tolist()
        train_groups = groups[train_idx].tolist()
        test_texts = texts[test_idx].tolist()
        model.fit(train_texts, train_labels)
        probabilities = model.predict_proba(test_texts)
        model_classes = list(model.named_steps["classifier"].classes_)
        aligned = np.zeros((len(test_idx), len(classes)), dtype=np.float64)
        for source_index, label in enumerate(model_classes):
            aligned[:, class_index[label]] = probabilities[:, source_index]
        pred_index = aligned.argmax(axis=1)
        predictions = np.asarray([classes[index] for index in pred_index], dtype=object)
        oof_pred[test_idx] = predictions
        oof_probs[test_idx] = aligned
        oof_raw[test_idx] = aligned.max(axis=1)

        prototypes = build_family_prototypes(model.named_steps["tfidf"], train_texts, train_labels, train_groups)
        scores = contrastive_family_scores(model.named_steps["tfidf"], prototypes, test_texts, predictions.tolist())
        for local, global_index in enumerate(test_idx):
            score = scores[local]
            oof_pred_similarity[global_index] = float(score["predicted_similarity"])
            oof_competing_similarity[global_index] = float(score["competing_similarity"])
            oof_margin[global_index] = float(score["contrast_margin"])
            oof_pred_family[global_index] = score["predicted_family"]
            oof_competing_family[global_index] = score["competing_family"]
            oof_competing_label[global_index] = score["competing_label"]
        fold_metrics.append({
            "fold": fold,
            "balanced_accuracy": float(deps["balanced_accuracy_score"](labels[test_idx], predictions)),
            "macro_f1": float(deps["f1_score"](labels[test_idx], predictions, average="macro", zero_division=0)),
            "examples": int(len(test_idx)),
            "families": int(len(set(groups[test_idx].tolist()))),
        })

    correct = oof_pred == labels
    global_calibrator = deps["IsotonicRegression"](y_min=0.0, y_max=1.0, out_of_bounds="clip")
    global_calibrator.fit(oof_raw, correct.astype(np.float64))
    class_calibrators: dict[str, Any] = {}
    for label in classes:
        mask = oof_pred == label
        calibrator = fit_isotonic(
            deps,
            oof_raw[mask],
            correct[mask].astype(np.float64),
            min_examples=min_class_calibration_examples,
        )
        if calibrator is not None:
            class_calibrators[label] = calibrator

    calibrated = np.zeros(len(rows), dtype=np.float64)
    confidence_sources: list[str] = []
    for index in range(len(rows)):
        calibrated[index], source = calibrate_confidence(
            str(oof_pred[index]), float(oof_raw[index]),
            global_calibrator=global_calibrator,
            class_calibrators=class_calibrators,
        )
        confidence_sources.append(source)

    class_policies: dict[str, dict[str, Any]] = {}
    for label in classes:
        mask = oof_pred == label
        accept = choose_precision_threshold(
            calibrated[mask].tolist(), correct[mask].tolist(),
            target_precision=accept_precision, min_examples=min_class_threshold_examples,
        )
        review = choose_precision_threshold(
            calibrated[mask].tolist(), correct[mask].tolist(),
            target_precision=review_precision, min_examples=min_class_threshold_examples,
        )
        accept_threshold = float(accept["threshold"]) if accept else None
        review_threshold = float(review["threshold"]) if review else None
        if accept_threshold is not None and review_threshold is not None:
            accept_threshold = max(accept_threshold, review_threshold)

        candidates = mask.copy()
        if accept_threshold is None:
            candidates[:] = False
        else:
            candidates &= calibrated >= accept_threshold
        similarity_policy = None
        if int(candidates.sum()) >= min_ood_threshold_examples:
            similarity_policy = choose_precision_threshold(
                oof_pred_similarity[candidates].tolist(), correct[candidates].tolist(),
                target_precision=accept_precision, min_examples=min_ood_threshold_examples,
            )
        similarity_threshold = float(similarity_policy["threshold"]) if similarity_policy else None

        contrast_candidates = candidates.copy()
        if similarity_threshold is None:
            contrast_candidates[:] = False
        else:
            contrast_candidates &= oof_pred_similarity >= similarity_threshold
        contrast_policy = None
        if int(contrast_candidates.sum()) >= min_ood_threshold_examples:
            contrast_policy = choose_precision_threshold(
                oof_margin[contrast_candidates].tolist(), correct[contrast_candidates].tolist(),
                target_precision=accept_precision, min_examples=min_ood_threshold_examples,
            )
        learned_margin = float(contrast_policy["threshold"]) if contrast_policy else None
        contrast_threshold = max(0.0, learned_margin) if learned_margin is not None else None
        predicted_examples = int(mask.sum())
        class_policies[label] = {
            "predicted_examples": predicted_examples,
            "oof_precision": float(correct[mask].mean()) if predicted_examples else 0.0,
            "confidence_calibrator": "classwise" if label in class_calibrators else "global_fallback",
            "accept": accept,
            "review": review,
            "accept_threshold": accept_threshold,
            "review_threshold": review_threshold,
            "ood_accept": similarity_policy,
            "ood_accept_threshold": similarity_threshold,
            "contrast_accept": contrast_policy,
            "contrast_accept_threshold": contrast_threshold,
            "contrast_learned_threshold": learned_margin,
        }

    actions = [
        route_action_with_contrastive_ood(
            str(oof_pred[index]), float(calibrated[index]),
            float(oof_pred_similarity[index]), float(oof_margin[index]), class_policies,
        )
        for index in range(len(rows))
    ]
    metrics = {
        "accuracy": float(deps["accuracy_score"](labels, oof_pred)),
        "balanced_accuracy": float(deps["balanced_accuracy_score"](labels, oof_pred)),
        "macro_f1": float(deps["f1_score"](labels, oof_pred, average="macro", zero_division=0)),
    }
    selective = selective_summary(actions, correct, np)

    final_model = make_model(deps, seed)
    final_model.fit(texts.tolist(), labels.tolist())
    family_prototypes = build_family_prototypes(
        final_model.named_steps["tfidf"], texts.tolist(), labels.tolist(), groups.tolist()
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    artifact = {
        "format": SELECTIVE_CLASSIFIER_FORMAT,
        "task": task,
        "classes": classes,
        "model": final_model,
        "confidence_calibrator": global_calibrator,
        "class_confidence_calibrators": class_calibrators,
        "class_policies": class_policies,
        "family_prototypes": family_prototypes,
    }
    deps["joblib"].dump(artifact, output_dir / "classifier.joblib")
    manifest = {
        "format": SELECTIVE_CLASSIFIER_FORMAT,
        "task": task,
        "classes": classes,
        "functions": len(rows),
        "families": len(set(groups.tolist())),
        "prototype_families": len(family_prototypes["families"]),
        "class_distribution": dict(sorted(Counter(labels.tolist()).items())),
        "dataset_fingerprint_sha256": sha256_rows(rows),
        "representation": "portable_pcode_ops_only",
        "model": {
            "kind": "tfidf_logistic_regression",
            "ngram_range": [1, 2], "min_df": 2, "max_features": 80000,
            "class_weight": "balanced",
        },
        "calibration": {
            "kind": "predicted_class_isotonic_correctness_probability",
            "source": "family_grouped_oof", "folds": folds, "seed": seed,
            "metrics": metrics, "fold_metrics": fold_metrics,
        },
        "routing": {
            "kind": "classwise_confidence_plus_contrastive_family_ood",
            "accept_target_precision": accept_precision,
            "review_target_precision": review_precision,
            "class_policies": class_policies,
            "oof_action_counts": dict(sorted(Counter(actions).items())),
            "selective_oof": selective,
        },
        "leakage_policy": {
            "function_names_used": False,
            "addresses_used": False,
            "raw_headers_used": False,
            "binary_identity_used": False,
            "labels_used_as_model_features": False,
            "family_grouped_calibration": True,
            "family_grouped_ood_thresholds": True,
        },
    }
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with (output_dir / "oof_predictions.jsonl").open("w", encoding="utf-8") as handle:
        for index, row in enumerate(rows):
            prediction = str(oof_pred[index])
            policy = class_policies[prediction]
            result = {
                "format": SELECTIVE_CLASSIFIER_FORMAT,
                "id": row["id"], "family_id": row["family_id"],
                "truth": row["label"], "prediction": prediction,
                "correct": bool(correct[index]),
                "raw_confidence": float(oof_raw[index]),
                "confidence": float(calibrated[index]),
                "confidence_source": confidence_sources[index],
                "family_similarity": float(oof_pred_similarity[index]),
                "nearest_training_family": oof_pred_family[index],
                "competing_similarity": float(oof_competing_similarity[index]),
                "nearest_competing_family": oof_competing_family[index],
                "nearest_competing_label": oof_competing_label[index],
                "contrast_margin": float(oof_margin[index]),
                "accept_threshold": policy.get("accept_threshold"),
                "review_threshold": policy.get("review_threshold"),
                "ood_accept_threshold": policy.get("ood_accept_threshold"),
                "contrast_accept_threshold": policy.get("contrast_accept_threshold"),
                "action": actions[index],
                "probabilities": {classes[position]: float(oof_probs[index, position]) for position in range(len(classes))},
            }
            handle.write(json.dumps(result, sort_keys=True) + "\n")
    return manifest


def extract_record(row: dict[str, Any], line_no: int) -> tuple[str, str]:
    text = row.get("model_text")
    if not isinstance(text, str) or not text:
        text = row.get("text")
    if not isinstance(text, str) or not text:
        raise ValueError(f"input row {line_no} has neither model_text nor text")
    record_id = row.get("id")
    if not isinstance(record_id, str) or not record_id:
        program, source_entry = row.get("program"), row.get("source_entry")
        record_id = f"{program}:{source_entry}" if isinstance(program, str) and isinstance(source_entry, str) else f"row-{line_no}"
    return record_id, normalize_portable(text)


def classify_rows(artifact: dict[str, Any], rows: list[dict[str, Any]], *, include_probabilities: bool = True) -> list[dict[str, Any]]:
    if artifact.get("format") != SELECTIVE_CLASSIFIER_FORMAT:
        raise ValueError(f"unsupported artifact format: {artifact.get('format')!r}")
    model = artifact["model"]
    classes = list(artifact["classes"])
    ids: list[str] = []
    texts: list[str] = []
    for line_no, row in enumerate(rows, 1):
        record_id, text = extract_record(row, line_no)
        ids.append(record_id)
        texts.append(text)
    if not rows:
        return []

    probabilities = model.predict_proba(texts)
    model_classes = list(model.named_steps["classifier"].classes_)
    positions = {label: index for index, label in enumerate(model_classes)}
    predictions: list[str] = []
    probability_maps: list[dict[str, float]] = []
    raw_confidences: list[float] = []
    for row_index in range(len(rows)):
        probability_map = {label: float(probabilities[row_index, positions[label]]) for label in classes}
        prediction = max(probability_map, key=probability_map.get)
        predictions.append(prediction)
        probability_maps.append(probability_map)
        raw_confidences.append(probability_map[prediction])

    scores = contrastive_family_scores(
        model.named_steps["tfidf"], artifact["family_prototypes"], texts, predictions
    )
    results: list[dict[str, Any]] = []
    for index, record_id in enumerate(ids):
        prediction = predictions[index]
        raw_confidence = raw_confidences[index]
        confidence, confidence_source = calibrate_confidence(
            prediction, raw_confidence,
            global_calibrator=artifact["confidence_calibrator"],
            class_calibrators=artifact.get("class_confidence_calibrators", {}),
        )
        score = scores[index]
        family_similarity = float(score["predicted_similarity"])
        contrast_margin = float(score["contrast_margin"])
        policy = artifact.get("class_policies", {}).get(prediction, {})
        action = route_action_with_contrastive_ood(
            prediction, confidence, family_similarity, contrast_margin,
            artifact.get("class_policies", {}),
        )
        result = {
            "format": SELECTIVE_CLASSIFIER_FORMAT,
            "id": record_id,
            "task": artifact["task"],
            "prediction": prediction,
            "raw_confidence": raw_confidence,
            "confidence": confidence,
            "confidence_source": confidence_source,
            "action": action,
            "accept_threshold": policy.get("accept_threshold"),
            "review_threshold": policy.get("review_threshold"),
            "family_similarity": family_similarity,
            "nearest_training_family": score["predicted_family"],
            "competing_similarity": float(score["competing_similarity"]),
            "nearest_competing_family": score["competing_family"],
            "nearest_competing_label": score["competing_label"],
            "contrast_margin": contrast_margin,
            "ood_accept_threshold": policy.get("ood_accept_threshold"),
            "contrast_accept_threshold": policy.get("contrast_accept_threshold"),
        }
        if include_probabilities:
            result["probabilities"] = probability_maps[index]
        results.append(result)
    return results


def train_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train REVENGINSTR.SelectiveClassifier/1")
    parser.add_argument("dataset_dir", type=Path)
    parser.add_argument("families", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--task", default="code_domain")
    parser.add_argument("--classes", nargs="+", required=True)
    parser.add_argument("--folds", type=int, default=5)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--accept-precision", type=float, default=0.95)
    parser.add_argument("--review-precision", type=float, default=0.85)
    parser.add_argument("--min-class-calibration-examples", type=int, default=25)
    parser.add_argument("--min-class-threshold-examples", type=int, default=10)
    parser.add_argument("--min-ood-threshold-examples", type=int, default=10)
    args = parser.parse_args(argv)
    manifest = train_selective_classifier(
        args.dataset_dir, args.families, args.output_dir,
        task=args.task, classes=args.classes, folds=args.folds, seed=args.seed,
        accept_precision=args.accept_precision, review_precision=args.review_precision,
        min_class_calibration_examples=args.min_class_calibration_examples,
        min_class_threshold_examples=args.min_class_threshold_examples,
        min_ood_threshold_examples=args.min_ood_threshold_examples,
    )
    print("format:", manifest["format"])
    print("functions:", manifest["functions"])
    print("families:", manifest["families"])
    print("metrics:", manifest["calibration"]["metrics"])
    print("actions:", manifest["routing"]["oof_action_counts"])
    print("artifact:", args.output_dir / "classifier.joblib")
    return 0


def _open_input(path: str) -> tuple[TextIO, bool]:
    if path == "-":
        return sys.stdin, False
    return Path(path).open("r", encoding="utf-8"), True


def _open_output(path: str | None) -> tuple[TextIO, bool]:
    if path is None or path == "-":
        return sys.stdout, False
    return Path(path).open("w", encoding="utf-8"), True


def infer_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run REVENGINSTR.SelectiveClassifier/1")
    parser.add_argument("model_dir", type=Path)
    parser.add_argument("input", help="JSONL corpus/dataset path, or -")
    parser.add_argument("--output", help="JSONL output path; default stdout")
    parser.add_argument("--no-probabilities", action="store_true")
    args = parser.parse_args(argv)
    deps = require_dependencies()
    artifact = deps["joblib"].load(args.model_dir / "classifier.joblib")
    input_handle, close_input = _open_input(args.input)
    output_handle, close_output = _open_output(args.output)
    try:
        rows = [json.loads(line) for line in input_handle if line.strip()]
        for result in classify_rows(artifact, rows, include_probabilities=not args.no_probabilities):
            output_handle.write(json.dumps(result, sort_keys=True) + "\n")
    finally:
        if close_input:
            input_handle.close()
        if close_output:
            output_handle.close()
    return 0
