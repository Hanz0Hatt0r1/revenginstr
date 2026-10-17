"""Report classifier performance by caller-supplied evaluation subgroups."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from revenginstr.ml import SELECTIVE_CLASSIFIER_FORMAT
from revenginstr.ml.selective import read_jsonl

FORMAT = "REVENGINSTR.SelectiveSubgroupAudit/1"
SUBGROUP_FORMAT = "REVENGINSTR.EvaluationSubgroup/1"
EVALUATION_FORMAT = "REVENGINSTR.SelectiveThresholdEvaluation/1"
ROUTE_ACTIONS = ("accept", "review", "escalate")


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


def _reliability(rows: list[dict[str, Any]], bin_count: int) -> dict[str, Any]:
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
    count = len(rows)
    return {
        "sample_count": count,
        "brier_score": sum((row["confidence"] - float(row["correct"])) ** 2 for row in rows) / count,
        "expected_calibration_error": sum(
            item["count"] * abs(item["mean_confidence"] - item["observed_accuracy"])
            for item in bins if item["count"]
        ) / count,
        "bins": bins,
    }


def build_subgroup_audit(
    evaluation_report: dict[str, Any],
    evaluation_rows: list[dict[str, Any]],
    subgroup_rows: list[dict[str, Any]],
    *,
    evaluation_report_sha256: str,
    predictions_sha256: str,
    subgroups_sha256: str,
) -> dict[str, Any]:
    if not isinstance(evaluation_report, dict) or evaluation_report.get("format") != EVALUATION_FORMAT:
        raise ValueError("unsupported threshold evaluation report format")
    source = evaluation_report.get("source")
    classes = evaluation_report.get("classes")
    bin_count = evaluation_report.get("bin_count")
    if (
        not isinstance(source, dict)
        or source.get("family_disjoint") is not True
        or source.get("classifier_format") != SELECTIVE_CLASSIFIER_FORMAT
        or source.get("evaluation_predictions_sha256") != predictions_sha256
        or not isinstance(classes, dict)
        or len(classes) < 2
        or any(not isinstance(label, str) or not label for label in classes)
        or isinstance(bin_count, bool)
        or not isinstance(bin_count, int)
        or not 1 <= bin_count <= 1000
    ):
        raise ValueError("evaluation report does not match a family-disjoint prediction input")
    if not all(_is_sha256(value) for value in (evaluation_report_sha256, predictions_sha256, subgroups_sha256)):
        raise ValueError("input provenance must contain SHA-256 digests")
    if not evaluation_rows or not subgroup_rows:
        raise ValueError("evaluation predictions and subgroup rows must not be empty")

    allowed = set(classes)
    seen_ids: set[str] = set()
    families: set[str] = set()
    groups_by_id: dict[str, str] = {}
    records: list[dict[str, Any]] = []
    for line_no, row in enumerate(evaluation_rows, 1):
        if not isinstance(row, dict) or row.get("format") != SELECTIVE_CLASSIFIER_FORMAT:
            raise ValueError(f"evaluation row {line_no}: unsupported format")
        record_id, family_id = row.get("id"), row.get("family_id")
        truth, prediction = row.get("truth"), row.get("prediction")
        correct, confidence, action = row.get("correct"), row.get("confidence"), row.get("action")
        if not isinstance(record_id, str) or not record_id or record_id in seen_ids:
            raise ValueError(f"evaluation row {line_no}: invalid or duplicate id")
        if not isinstance(family_id, str) or not family_id:
            raise ValueError(f"evaluation row {line_no}: invalid family_id")
        if (
            not isinstance(truth, str) or truth not in allowed
            or not isinstance(prediction, str) or prediction not in allowed
        ):
            raise ValueError(f"evaluation row {line_no}: truth or prediction outside evaluated classes")
        if not isinstance(correct, bool) or correct != (truth == prediction):
            raise ValueError(f"evaluation row {line_no}: correct flag disagrees with truth and prediction")
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            raise ValueError(f"evaluation row {line_no}: invalid calibrated confidence")
        try:
            confidence = float(confidence)
        except OverflowError as exc:
            raise ValueError(f"evaluation row {line_no}: invalid calibrated confidence") from exc
        if not math.isfinite(confidence) or not 0.0 <= confidence <= 1.0:
            raise ValueError(f"evaluation row {line_no}: invalid calibrated confidence")
        if not isinstance(action, str) or action not in ROUTE_ACTIONS:
            raise ValueError(f"evaluation row {line_no}: invalid route action")
        seen_ids.add(record_id)
        families.add(family_id)
        records.append({
            "id": record_id,
            "truth": truth,
            "prediction": prediction,
            "correct": correct,
            "confidence": confidence,
            "action": action,
        })

    for line_no, row in enumerate(subgroup_rows, 1):
        if not isinstance(row, dict) or row.get("format") != SUBGROUP_FORMAT:
            raise ValueError(f"subgroup row {line_no}: unsupported format")
        record_id, subgroup = row.get("id"), row.get("subgroup")
        if not isinstance(record_id, str) or record_id not in seen_ids or record_id in groups_by_id:
            raise ValueError(f"subgroup row {line_no}: invalid, duplicate, or unknown id")
        if not isinstance(subgroup, str) or not subgroup:
            raise ValueError(f"subgroup row {line_no}: invalid subgroup")
        groups_by_id[record_id] = subgroup
    if set(groups_by_id) != seen_ids:
        raise ValueError("subgroup mapping must cover every evaluation id exactly once")

    evaluation_rows_count = source.get("evaluation_rows")
    evaluation_families_count = source.get("evaluation_families")
    if (
        isinstance(evaluation_rows_count, bool)
        or not isinstance(evaluation_rows_count, int)
        or evaluation_rows_count != len(records)
        or isinstance(evaluation_families_count, bool)
        or not isinstance(evaluation_families_count, int)
        or evaluation_families_count != len(families)
    ):
        raise ValueError("evaluation population counts disagree with threshold report")

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in records:
        grouped[groups_by_id[row["id"]]].append(row)

    group_results = {}
    for subgroup, rows in sorted(grouped.items()):
        action_counts = Counter(row["action"] for row in rows)
        accepted = [row for row in rows if row["action"] == "accept"]
        class_counts = {
            label: {"truth_rows": 0, "predicted_rows": 0, "true_positive_rows": 0}
            for label in sorted(classes)
        }
        for row in rows:
            class_counts[row["truth"]]["truth_rows"] += 1
            class_counts[row["prediction"]]["predicted_rows"] += 1
            if row["correct"]:
                class_counts[row["truth"]]["true_positive_rows"] += 1
        correct_rows = sum(row["correct"] for row in rows)
        group_results[subgroup] = {
            "rows": len(rows),
            "correct_rows": correct_rows,
            "accuracy": correct_rows / len(rows),
            "calibration": _reliability(rows, bin_count),
            "action_counts": {action: action_counts[action] for action in ROUTE_ACTIONS},
            "accepted_rows": len(accepted),
            "accepted_precision": (
                sum(row["correct"] for row in accepted) / len(accepted) if accepted else None
            ),
            "accepted_coverage": len(accepted) / len(rows),
            "class_counts": class_counts,
        }
    return {
        "format": FORMAT,
        "source": {
            "evaluation_report_sha256": evaluation_report_sha256,
            "evaluation_predictions_sha256": predictions_sha256,
            "subgroups_sha256": subgroups_sha256,
            "evaluation_rows": len(records),
            "evaluation_families": len(families),
            "subgroup_count": len(grouped),
            "family_disjoint": True,
        },
        "groups": group_results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("threshold_evaluation_json", type=Path)
    parser.add_argument("evaluation_predictions_jsonl", type=Path)
    parser.add_argument("subgroups_jsonl", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    report_bytes = args.threshold_evaluation_json.read_bytes()
    report = json.loads(report_bytes)
    evaluation_rows = list(read_jsonl(args.evaluation_predictions_jsonl))
    subgroup_rows = list(read_jsonl(args.subgroups_jsonl))
    result = build_subgroup_audit(
        report,
        evaluation_rows,
        subgroup_rows,
        evaluation_report_sha256=hashlib.sha256(report_bytes).hexdigest(),
        predictions_sha256=_sha256(args.evaluation_predictions_jsonl),
        subgroups_sha256=_sha256(args.subgroups_jsonl),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("evaluation rows:", result["source"]["evaluation_rows"])
    print("subgroups:", result["source"]["subgroup_count"])
    print("output:", args.output)
    return 0
