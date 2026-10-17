"""Score paired, adjudicated multi-label function-role predictions."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

FORMAT = "REVENGINSTR.SemanticRoleEvaluation/1"
LABEL_FORMAT = "REVENGINSTR.SemanticRoleLabel/1"
PREDICTION_FORMAT = "REVENGINSTR.SemanticRolePrediction/1"
FAMILY_FORMAT = "REVENGINSTR.FunctionFamilies/1"
ROLES = (
    "lifecycle_init_shutdown",
    "accessor_getter_setter",
    "constructor_destructor_factory",
    "parser_decoder_loader",
    "serializer_save_writer",
    "state_update_tick",
    "input_handler",
    "render_submission",
    "animation_action_update",
    "physics_collision_query",
    "combat_state_transition",
    "resource_lookup_cache",
    "callback_scheduler_adapter",
    "network_media_runtime_adapter",
    "utility_container_math",
    "unknown",
    "compound",
)
_ROLE_SET = set(ROLES)


def _read_jsonl(path: Path) -> tuple[str, list[dict[str, Any]]]:
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"{path}: input must be UTF-8") from error
    rows: list[dict[str, Any]] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            raise ValueError(f"{path}:{line_no}: blank JSONL record")
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"{path}:{line_no}: invalid JSON") from error
        if not isinstance(row, dict):
            raise ValueError(f"{path}:{line_no}: expected object")
        rows.append(row)
    if not rows:
        raise ValueError(f"{path}: expected at least one JSONL record")
    return hashlib.sha256(raw).hexdigest(), rows


def _nonempty_string(row: dict[str, Any], field: str, where: str) -> str:
    value = row.get(field)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{where}: invalid {field}")
    return value


def _roles(value: Any, where: str) -> set[str]:
    if not isinstance(value, list) or not value or any(not isinstance(role, str) for role in value):
        raise ValueError(f"{where}: roles must be a non-empty string array")
    if len(value) != len(set(value)) or not set(value) <= _ROLE_SET:
        raise ValueError(f"{where}: duplicate or unsupported role")
    return set(value)


def _read_role_rows(
    path: Path,
    *,
    expected_format: str,
    prediction: bool,
) -> tuple[str, dict[str, str], dict[str, tuple[str, set[str]]]]:
    digest, rows = _read_jsonl(path)
    expected_fields = {
        "format", "dataset_id", "split_id", "id", "family_id", "roles",
        "model_id" if prediction else "adjudication_status",
    }
    indexed: dict[str, tuple[str, set[str]]] = {}
    metadata: dict[str, str] = {}
    for record_index, row in enumerate(rows, 1):
        where = f"{path}:record {record_index}"
        if set(row) != expected_fields or row.get("format") != expected_format:
            raise ValueError(f"{where}: unexpected format or fields")
        dataset_id = _nonempty_string(row, "dataset_id", where)
        split_id = _nonempty_string(row, "split_id", where)
        record_id = _nonempty_string(row, "id", where)
        family_id = _nonempty_string(row, "family_id", where)
        record_roles = _roles(row.get("roles"), where)
        if not prediction and row.get("adjudication_status") != "adjudicated":
            raise ValueError(f"{where}: label is not adjudicated")
        if prediction:
            model_id = _nonempty_string(row, "model_id", where)
        else:
            model_id = ""
        row_metadata = {"dataset_id": dataset_id, "split_id": split_id}
        if prediction:
            row_metadata["model_id"] = model_id
        if metadata and row_metadata != metadata:
            raise ValueError(f"{where}: mixed dataset, split, or model identity")
        metadata = row_metadata
        if record_id in indexed:
            raise ValueError(f"{where}: duplicate function id")
        indexed[record_id] = (family_id, record_roles)
    return digest, metadata, indexed


def _training_families(path: Path) -> tuple[str, set[str], set[str]]:
    digest, rows = _read_jsonl(path)
    seen_ids: set[str] = set()
    families: set[str] = set()
    for record_index, row in enumerate(rows, 1):
        where = f"{path}:record {record_index}"
        expected = {"format", "id", "family_id", "family_size", "portable_hash", "feature_count"}
        if set(row) != expected or row.get("format") != FAMILY_FORMAT:
            raise ValueError(f"{where}: unsupported function-family row")
        record_id = _nonempty_string(row, "id", where)
        family_id = _nonempty_string(row, "family_id", where)
        if not re.fullmatch(r"family-[0-9a-f]{20}", family_id):
            raise ValueError(f"{where}: invalid family_id")
        if record_id in seen_ids:
            raise ValueError(f"{where}: duplicate function id")
        if type(row["family_size"]) is not int or row["family_size"] < 1:
            raise ValueError(f"{where}: invalid family_size")
        if type(row["feature_count"]) is not int or row["feature_count"] < 0:
            raise ValueError(f"{where}: invalid feature_count")
        if not isinstance(row["portable_hash"], str) or not re.fullmatch(r"[0-9a-f]{24}", row["portable_hash"]):
            raise ValueError(f"{where}: invalid portable_hash")
        seen_ids.add(record_id)
        families.add(family_id)
    return digest, families, seen_ids


def _role_metric(
    true_positive: int, false_positive: int, false_negative: int
) -> dict[str, int | float]:
    support = true_positive + false_negative
    predicted_count = true_positive + false_positive
    precision = true_positive / predicted_count if predicted_count else 0.0
    recall = true_positive / support if support else 0.0
    denominator = 2 * true_positive + false_positive + false_negative
    f1 = 2 * true_positive / denominator if denominator else 0.0
    return {
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "support": support,
        "predicted_count": predicted_count,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def evaluate_semantic_roles(
    labels_path: Path,
    predictions_path: Path,
    *,
    training_families_path: Path | None = None,
) -> dict[str, Any]:
    """Evaluate exact paired multi-label predictions and optionally certify family separation."""
    label_hash, label_meta, labels = _read_role_rows(
        labels_path, expected_format=LABEL_FORMAT, prediction=False
    )
    prediction_hash, prediction_meta, predictions = _read_role_rows(
        predictions_path, expected_format=PREDICTION_FORMAT, prediction=True
    )
    if {key: label_meta[key] for key in ("dataset_id", "split_id")} != {
        key: prediction_meta[key] for key in ("dataset_id", "split_id")
    }:
        raise ValueError("label and prediction dataset/split identities differ")
    if labels.keys() != predictions.keys():
        raise ValueError("label and prediction ids do not match exactly")
    for record_id, (family_id, _roles_for_row) in labels.items():
        if predictions[record_id][0] != family_id:
            raise ValueError("label and prediction family ids differ")

    training_hash = None
    family_disjointness = "not_checked"
    evaluation_families = {family_id for family_id, _ in labels.values()}
    if training_families_path is not None:
        training_hash, training_families, training_ids = _training_families(training_families_path)
        evaluation_ids = set(labels)
        if evaluation_ids & training_ids:
            raise ValueError("evaluation and training function ids overlap")
        if evaluation_families & training_families:
            raise ValueError("evaluation and training family sets overlap")
        family_disjointness = "verified"

    role_counts = {
        role: {"tp": 0, "fp": 0, "fn": 0}
        for role in ROLES
    }
    exact_matches = 0
    for record_id, (_family_id, truth) in labels.items():
        predicted = predictions[record_id][1]
        exact_matches += truth == predicted
        for role in ROLES:
            counts = role_counts[role]
            counts["tp"] += int(role in truth and role in predicted)
            counts["fp"] += int(role not in truth and role in predicted)
            counts["fn"] += int(role in truth and role not in predicted)

    per_role: dict[str, dict[str, int | float]] = {}
    observed_f1: list[float] = []
    micro_tp = micro_fp = micro_fn = 0
    for role in ROLES:
        counts = role_counts[role]
        metric = _role_metric(counts["tp"], counts["fp"], counts["fn"])
        per_role[role] = metric
        if counts["tp"] + counts["fp"] + counts["fn"]:
            observed_f1.append(float(metric["f1"]))
        micro_tp += counts["tp"]
        micro_fp += counts["fp"]
        micro_fn += counts["fn"]

    micro_denominator = 2 * micro_tp + micro_fp + micro_fn
    return {
        "format": FORMAT,
        "dataset_id": label_meta["dataset_id"],
        "split_id": label_meta["split_id"],
        "model_id": prediction_meta["model_id"],
        "label_artifact_sha256": label_hash,
        "prediction_artifact_sha256": prediction_hash,
        "training_family_artifact_sha256": training_hash,
        "family_disjointness": family_disjointness,
        "rows": len(labels),
        "family_count": len(evaluation_families),
        "per_role": per_role,
        "macro_f1_observed_roles": len(observed_f1),
        "macro_f1_observed": sum(observed_f1) / len(observed_f1),
        "micro_f1": 2 * micro_tp / micro_denominator if micro_denominator else 0.0,
        "exact_match_accuracy": exact_matches / len(labels),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("labels", type=Path)
    parser.add_argument("predictions", type=Path)
    parser.add_argument("--training-families", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    report = evaluate_semantic_roles(
        args.labels,
        args.predictions,
        training_families_path=args.training_families,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    print("rows:", report["rows"])
    print("families:", report["family_count"])
    print("macro F1 (observed roles):", report["macro_f1_observed"])
    print("micro F1:", report["micro_f1"])
    print("exact match accuracy:", report["exact_match_accuracy"])
    print("family disjointness:", report["family_disjointness"])
    print("output:", args.output)
    return 0
