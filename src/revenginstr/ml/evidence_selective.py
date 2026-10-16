"""Project-neutral evidence-aware selective portable-P-code classifier.

This is the reusable mechanism behind the Nevergone v5 evidence-fusion line:
portable P-code is augmented with coarse structural and external numeric evidence
before the same family-grouped classification/calibration/contrastive-OOD policy
used by the P-code-only selective baseline.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

from .evidence_tokens import EVIDENCE_FORMAT, augment_text, load_evidence
from .selective import (
    calibrate_confidence,
    choose_precision_threshold,
    extract_record,
    fit_isotonic,
    load_dataset,
    make_model,
    normalize_portable,
    require_dependencies,
    route_action_with_contrastive_ood,
    selective_summary,
    sha256_rows,
)
from .similarity import build_family_prototypes, contrastive_family_scores

FORMAT = "REVENGINSTR.EvidenceSelectiveClassifier/1"


def _sha256_evidence(evidence: dict[str, dict[str, float]]) -> str:
    digest = hashlib.sha256()
    for record_id in sorted(evidence):
        digest.update(record_id.encode("utf-8"))
        digest.update(b"\0")
        digest.update(
            json.dumps(evidence[record_id], sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        digest.update(b"\n")
    return digest.hexdigest()


def _build_class_policies(*, classes: list[str], predictions, calibrated, correct,
                          pred_similarity, margin, class_calibrators,
                          accept_precision: float, review_precision: float,
                          min_class_threshold_examples: int,
                          min_ood_threshold_examples: int) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for label in classes:
        mask = predictions == label
        accept = choose_precision_threshold(
            calibrated[mask].tolist(), correct[mask].tolist(),
            target_precision=accept_precision,
            min_examples=min_class_threshold_examples,
        )
        review = choose_precision_threshold(
            calibrated[mask].tolist(), correct[mask].tolist(),
            target_precision=review_precision,
            min_examples=min_class_threshold_examples,
        )
        accept_threshold = float(accept["threshold"]) if accept else None
        review_threshold = float(review["threshold"]) if review else None
        if accept_threshold is not None and review_threshold is not None:
            accept_threshold = max(accept_threshold, review_threshold)

        confidence_candidates = mask.copy()
        if accept_threshold is None:
            confidence_candidates[:] = False
        else:
            confidence_candidates &= calibrated >= accept_threshold

        similarity_policy = None
        if int(confidence_candidates.sum()) >= min_ood_threshold_examples:
            similarity_policy = choose_precision_threshold(
                pred_similarity[confidence_candidates].tolist(),
                correct[confidence_candidates].tolist(),
                target_precision=accept_precision,
                min_examples=min_ood_threshold_examples,
            )
        similarity_threshold = float(similarity_policy["threshold"]) if similarity_policy else None

        contrast_candidates = confidence_candidates.copy()
        if similarity_threshold is None:
            contrast_candidates[:] = False
        else:
            contrast_candidates &= pred_similarity >= similarity_threshold
        contrast_policy = None
        if int(contrast_candidates.sum()) >= min_ood_threshold_examples:
            contrast_policy = choose_precision_threshold(
                margin[contrast_candidates].tolist(),
                correct[contrast_candidates].tolist(),
                target_precision=accept_precision,
                min_examples=min_ood_threshold_examples,
            )
        learned_margin = float(contrast_policy["threshold"]) if contrast_policy else None
        contrast_threshold = max(0.0, learned_margin) if learned_margin is not None else None
        predicted_examples = int(mask.sum())
        result[label] = {
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
            "ood_accept_candidate_examples": int(confidence_candidates.sum()),
            "contrast_candidate_examples": int(contrast_candidates.sum()),
        }
    return result


def train_evidence_selective_classifier(dataset_dir: Path, families_path: Path,
                                         output_dir: Path, *, evidence_path: Path | None,
                                         task: str, classes: list[str], folds: int = 5,
                                         seed: int = 42, accept_precision: float = 0.95,
                                         review_precision: float = 0.85,
                                         min_class_calibration_examples: int = 25,
                                         min_class_threshold_examples: int = 10,
                                         min_ood_threshold_examples: int = 10) -> dict[str, Any]:
    if folds < 2:
        raise ValueError("folds must be >= 2")
    if review_precision > accept_precision:
        raise ValueError("review_precision must be <= accept_precision")
    deps = require_dependencies()
    np = deps["np"]
    rows = load_dataset(dataset_dir, families_path, task=task, classes=classes)
    external = load_evidence(evidence_path)

    documents: list[str] = []
    evidence_counts: list[int] = []
    external_presence: list[bool] = []
    for row in rows:
        ext = external.get(row["id"], {})
        document, count = augment_text(row["text"], ext)
        documents.append(document)
        evidence_counts.append(count)
        external_presence.append(bool(ext))

    texts = np.asarray(documents, dtype=object)
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

        vectorizer = model.named_steps["tfidf"]
        prototypes = build_family_prototypes(vectorizer, train_texts, train_labels, train_groups)
        scores = contrastive_family_scores(vectorizer, prototypes, test_texts, predictions.tolist())
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
            deps, oof_raw[mask], correct[mask].astype(np.float64),
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

    class_policies = _build_class_policies(
        classes=classes, predictions=oof_pred, calibrated=calibrated, correct=correct,
        pred_similarity=oof_pred_similarity, margin=oof_margin,
        class_calibrators=class_calibrators,
        accept_precision=accept_precision, review_precision=review_precision,
        min_class_threshold_examples=min_class_threshold_examples,
        min_ood_threshold_examples=min_ood_threshold_examples,
    )
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
    artifact = {
        "format": FORMAT,
        "task": task,
        "classes": classes,
        "model": final_model,
        "confidence_calibrator": global_calibrator,
        "class_confidence_calibrators": class_calibrators,
        "class_policies": class_policies,
        "family_prototypes": family_prototypes,
        "evidence_format": EVIDENCE_FORMAT,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    deps["joblib"].dump(artifact, output_dir / "classifier.joblib")

    manifest = {
        "format": FORMAT,
        "task": task,
        "classes": classes,
        "functions": len(rows),
        "families": len(set(groups.tolist())),
        "prototype_families": len(family_prototypes["families"]),
        "class_distribution": dict(sorted(Counter(labels.tolist()).items())),
        "dataset_fingerprint_sha256": sha256_rows(rows),
        "external_evidence_sha256": _sha256_evidence(external),
        "external_evidence_rows": sum(external_presence),
        "mean_evidence_tokens": sum(evidence_counts) / len(evidence_counts),
        "evidence_format": EVIDENCE_FORMAT,
        "representation": "portable_pcode_plus_bucketed_objective_evidence",
        "model": {"kind": "tfidf_logistic_regression", "ngram_range": [1, 2], "min_df": 2, "max_features": 80000, "class_weight": "balanced"},
        "calibration": {"kind": "predicted_class_isotonic_correctness_probability", "source": "family_grouped_oof", "folds": folds, "seed": seed, "metrics": metrics, "fold_metrics": fold_metrics},
        "routing": {"kind": "classwise_confidence_plus_contrastive_family_ood", "accept_target_precision": accept_precision, "review_target_precision": review_precision, "class_policies": class_policies, "oof_action_counts": dict(sorted(Counter(actions).items())), "selective_oof": selective},
        "leakage_policy": {"function_names_used": False, "addresses_used": False, "raw_receiver_class_names_used": False, "raw_vtable_identities_used": False, "labels_used_as_model_features": False, "numeric_evidence_bucketed": True, "family_grouped_calibration": True, "family_grouped_ood_thresholds": True},
    }
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with (output_dir / "oof_predictions.jsonl").open("w", encoding="utf-8") as handle:
        for index, row in enumerate(rows):
            prediction = str(oof_pred[index])
            policy = class_policies[prediction]
            handle.write(json.dumps({
                "format": FORMAT,
                "id": row["id"], "family_id": row["family_id"], "truth": row["label"],
                "prediction": prediction, "correct": bool(correct[index]),
                "raw_confidence": float(oof_raw[index]), "confidence": float(calibrated[index]),
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
                "evidence_token_count": evidence_counts[index],
                "external_evidence_present": external_presence[index],
                "probabilities": {classes[pos]: float(oof_probs[index, pos]) for pos in range(len(classes))},
            }, sort_keys=True) + "\n")
    return manifest


def classify_rows(artifact: dict[str, Any], rows: list[dict[str, Any]], *,
                  evidence: dict[str, dict[str, float]] | None = None,
                  include_probabilities: bool = True) -> list[dict[str, Any]]:
    if artifact.get("format") != FORMAT:
        raise ValueError(f"unsupported artifact format: {artifact.get('format')!r}")
    evidence = evidence or {}
    model = artifact["model"]
    classes = list(artifact["classes"])
    ids: list[str] = []
    documents: list[str] = []
    token_counts: list[int] = []
    external_presence: list[bool] = []
    for line_no, row in enumerate(rows, 1):
        record_id, text = extract_record(row, line_no)
        portable = normalize_portable(text)
        ext = evidence.get(record_id, {})
        document, count = augment_text(portable, ext)
        ids.append(record_id)
        documents.append(document)
        token_counts.append(count)
        external_presence.append(bool(ext))
    if not rows:
        return []

    probabilities = model.predict_proba(documents)
    model_classes = list(model.named_steps["classifier"].classes_)
    positions = {label: index for index, label in enumerate(model_classes)}
    probability_maps: list[dict[str, float]] = []
    predictions: list[str] = []
    for row_index in range(len(rows)):
        probability_map = {label: float(probabilities[row_index, positions[label]]) for label in classes}
        probability_maps.append(probability_map)
        predictions.append(max(probability_map, key=probability_map.get))
    scores = contrastive_family_scores(
        model.named_steps["tfidf"], artifact["family_prototypes"], documents, predictions
    )

    result: list[dict[str, Any]] = []
    for index, record_id in enumerate(ids):
        prediction = predictions[index]
        raw_confidence = probability_maps[index][prediction]
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
        row_result = {
            "format": FORMAT, "id": record_id, "task": artifact["task"],
            "prediction": prediction, "raw_confidence": raw_confidence,
            "confidence": confidence, "confidence_source": confidence_source,
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
            "evidence_token_count": token_counts[index],
            "external_evidence_present": external_presence[index],
        }
        if include_probabilities:
            row_result["probabilities"] = probability_maps[index]
        result.append(row_result)
    return result


def train_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Train REVENGINSTR.EvidenceSelectiveClassifier/1")
    parser.add_argument("dataset_dir", type=Path)
    parser.add_argument("families", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--evidence", type=Path)
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
    manifest = train_evidence_selective_classifier(
        args.dataset_dir, args.families, args.output_dir,
        evidence_path=args.evidence, task=args.task, classes=args.classes,
        folds=args.folds, seed=args.seed, accept_precision=args.accept_precision,
        review_precision=args.review_precision,
        min_class_calibration_examples=args.min_class_calibration_examples,
        min_class_threshold_examples=args.min_class_threshold_examples,
        min_ood_threshold_examples=args.min_ood_threshold_examples,
    )
    print("format:", manifest["format"])
    print("functions:", manifest["functions"])
    print("external evidence rows:", manifest["external_evidence_rows"])
    print("mean evidence tokens:", round(manifest["mean_evidence_tokens"], 3))
    print("metrics:", manifest["calibration"]["metrics"])
    print("actions:", manifest["routing"]["oof_action_counts"])
    print("artifact:", args.output_dir / "classifier.joblib")
    return 0


def infer_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run REVENGINSTR.EvidenceSelectiveClassifier/1")
    parser.add_argument("model_dir", type=Path)
    parser.add_argument("input", type=Path)
    parser.add_argument("--evidence", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--no-probabilities", action="store_true")
    args = parser.parse_args(argv)
    deps = require_dependencies()
    artifact = deps["joblib"].load(args.model_dir / "classifier.joblib")
    rows = [json.loads(line) for line in args.input.read_text(encoding="utf-8").splitlines() if line.strip()]
    external = load_evidence(args.evidence)
    results = classify_rows(
        artifact, rows, evidence=external,
        include_probabilities=not args.no_probabilities,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in results), encoding="utf-8")
    print("format:", FORMAT)
    print("rows:", len(results))
    print("output:", args.output)
    return 0
