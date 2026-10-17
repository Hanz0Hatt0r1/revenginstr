"""Project consumer-owned benchmark reports into a common metric summary."""
from __future__ import annotations

import json
import math
from collections import Counter
from pathlib import Path
from typing import Any


class MetricProjectionError(ValueError):
    """A projection input does not satisfy its declared metric contract."""


_RECEIVER_EVIDENCE_DIMENSIONS = (
    "exact_vtable_witness", "constructor_factory_witness", "field_layout_compatibility",
    "slot_compatibility", "caller_provenance", "callgraph_consistency", "runtime_witness",
)
_RECEIVER_EVIDENCE_STATES = {"supported", "contradicted", "unknown", "not_applicable"}
_RECEIVER_EVIDENCE_CLASSES = {
    "exact_static", "runtime_native", "derived_structural", "model_prediction",
    "human_review", "interventional_probe",
}


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise MetricProjectionError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
            if not isinstance(row, dict):
                raise MetricProjectionError(f"{path}:{line_no}: expected JSON object")
            rows.append(row)
    return rows


def _classification(rows: list[dict[str, Any]], config: dict[str, Any]) -> dict[str, Any]:
    truth_field = config.get("truth_field", "truth")
    prediction_field = config.get("prediction_field", "prediction")
    has_labels = all(
        isinstance(row.get(truth_field), str) and row[truth_field]
        and isinstance(row.get(prediction_field), str) and row[prediction_field]
        for row in rows
    )
    has_any_labels = any(truth_field in row or prediction_field in row for row in rows)
    if has_any_labels and not has_labels:
        raise MetricProjectionError("truth and prediction must be present and non-empty on every row, or omitted on every row")
    result: dict[str, Any] = {"row_count": len(rows)}
    if has_labels:
        truth = [row[truth_field] for row in rows]
        predictions = [row[prediction_field] for row in rows]
        labels = sorted(set(truth) | set(predictions))
        counts = Counter(zip(truth, predictions))
        distribution = Counter(truth)
        per_class: dict[str, Any] = {}
        f1_values: list[float] = []
        recalls: list[float] = []
        for label in labels:
            true_positive = counts[(label, label)]
            predicted_count = sum(counts[(actual, label)] for actual in labels)
            support = distribution[label]
            precision = true_positive / predicted_count if predicted_count else 0.0
            recall = true_positive / support if support else 0.0
            f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
            per_class[label] = {
                "precision": precision, "recall": recall, "f1": f1, "support": support,
            }
            f1_values.append(f1)
            if support:
                recalls.append(recall)
        result.update({
            "class_distribution": dict(sorted(distribution.items())),
            "classification": {
                "classes": labels,
                "confusion_matrix": [[counts[(actual, predicted)] for predicted in labels] for actual in labels],
                "per_class": per_class,
                "macro_f1": sum(f1_values) / len(f1_values) if f1_values else None,
                "balanced_accuracy": sum(recalls) / len(recalls) if recalls else None,
            },
        })

    action_field = config.get("action_field", "action")
    action_rows = sum(action_field in row for row in rows)
    if 0 < action_rows < len(rows):
        raise MetricProjectionError(f"{action_field!r} must be present on every row when routing actions are supplied")
    if action_rows:
        actions = [str(row.get(action_field, "<missing>")) for row in rows]
        action_counts = Counter(actions)
        accepted_actions = set(config.get("accepted_actions", ["accept"]))
        accepted = [index for index, action in enumerate(actions) if action in accepted_actions]
        coverage: dict[str, Any] = {
            "action_counts": dict(sorted(action_counts.items())),
            "accepted_rows": len(accepted),
            "abstained_rows": len(rows) - len(accepted),
            "accepted_fraction": len(accepted) / len(rows) if rows else None,
            "abstained_fraction": (len(rows) - len(accepted)) / len(rows) if rows else None,
        }
        if has_labels:
            coverage["accepted_accuracy"] = (
                sum(rows[index][truth_field] == rows[index][prediction_field] for index in accepted) / len(accepted)
                if accepted else None
            )
        result["coverage"] = coverage

    confidence_field = config.get("confidence_field", "confidence")
    scored = []
    if has_labels:
        for index, row in enumerate(rows):
            confidence = row.get(confidence_field)
            if confidence is None:
                continue
            if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
                raise MetricProjectionError(f"row {index + 1}: {confidence_field!r} must be numeric")
            confidence = float(confidence)
            if not math.isfinite(confidence) or not 0.0 <= confidence <= 1.0:
                raise MetricProjectionError(f"row {index + 1}: {confidence_field!r} must be finite and in [0, 1]")
            correct = float(row[truth_field] == row[prediction_field])
            scored.append((confidence, correct))
    if scored:
        bin_count = config.get("calibration_bins", 10)
        bins = []
        for bin_index in range(bin_count):
            lower = bin_index / bin_count
            upper = (bin_index + 1) / bin_count
            values = [(score, correct) for score, correct in scored
                      if lower <= score < upper or (bin_index == bin_count - 1 and score == 1.0)]
            bins.append({
                "lower_bound": lower, "upper_bound": upper, "count": len(values),
                "mean_confidence": sum(score for score, _ in values) / len(values) if values else None,
                "observed_accuracy": sum(correct for _, correct in values) / len(values) if values else None,
            })
        result["calibration"] = {
            "sample_count": len(scored), "excluded_count": len(rows) - len(scored), "bins": bins,
            "expected_calibration_error": sum(
                item["count"] * abs(item["mean_confidence"] - item["observed_accuracy"])
                for item in bins if item["count"]
            ) / len(scored),
            "brier_score": sum((score - correct) ** 2 for score, correct in scored) / len(scored),
        }
    return result


def _receiver(rows: list[dict[str, Any]], config: dict[str, Any]) -> dict[str, Any]:
    status_field = config.get("status_field", "status")
    if not all(isinstance(row.get(status_field), str) and row[status_field] for row in rows):
        raise MetricProjectionError(f"receiver rows must contain string field {status_field!r}")
    counts = Counter(row[status_field] for row in rows)
    resolved_statuses = set(config.get("resolved_statuses", ["resolved_unique_vtable"]))
    resolved = sum(count for status, count in counts.items() if status in resolved_statuses)
    return {
        "row_count": len(rows),
        "receiver": {
            "status_counts": dict(sorted(counts.items())),
            "resolved_rows": resolved,
            "coverage": resolved / len(rows) if rows else None,
        },
    }


def _receiver_assessment(rows: list[dict[str, Any]]) -> dict[str, Any]:
    statuses = {
        "no_known_candidates", "same_type_convergence", "compatible_subtype_candidates",
        "mixed_candidates", "partially_unknown_candidates",
    }
    status_counts: Counter[str] = Counter()
    candidate_count_counts: Counter[str] = Counter()
    rows_with_unknown_candidates = 0
    unknown_candidate_total = 0
    compatibility_group_rows = 0
    for row_number, row in enumerate(rows, 1):
        if row.get("format") != "REVENGINSTR.ReceiverCandidateAssessment/1":
            raise MetricProjectionError(f"assessment row {row_number}: unsupported format")
        status = row.get("status")
        if not isinstance(status, str) or status not in statuses:
            raise MetricProjectionError(f"assessment row {row_number}: invalid candidate status")
        candidates = row.get("candidate_receiver_class_names")
        if (not isinstance(candidates, list)
                or any(not isinstance(candidate, str) or not candidate for candidate in candidates)
                or len(set(candidates)) != len(candidates)):
            raise MetricProjectionError(f"assessment row {row_number}: invalid candidate list")
        unknown = row.get("unknown_type_candidate_count")
        if isinstance(unknown, bool) or not isinstance(unknown, int) or unknown < 0:
            raise MetricProjectionError(f"assessment row {row_number}: invalid unknown candidate count")
        group_id = row.get("compatibility_group_id")
        if group_id is not None and not isinstance(group_id, str):
            raise MetricProjectionError(f"assessment row {row_number}: invalid compatibility group")
        status_counts[status] += 1
        candidate_count_counts[str(len(candidates))] += 1
        rows_with_unknown_candidates += unknown > 0
        unknown_candidate_total += unknown
        compatibility_group_rows += group_id is not None
    return {
        "row_count": len(rows),
        "receiver_assessment": {
            "status_counts": dict(sorted(status_counts.items())),
            "candidate_count_counts": dict(sorted(candidate_count_counts.items(), key=lambda item: int(item[0]))),
            "rows_with_unknown_candidates": rows_with_unknown_candidates,
            "unknown_candidate_total": unknown_candidate_total,
            "compatibility_group_rows": compatibility_group_rows,
        },
    }


def _receiver_candidate_evidence(rows: list[dict[str, Any]]) -> dict[str, Any]:
    status_counts = {name: Counter() for name in _RECEIVER_EVIDENCE_DIMENSIONS}
    evidence_class_counts = {name: Counter() for name in _RECEIVER_EVIDENCE_DIMENSIONS}
    for row_number, row in enumerate(rows, 1):
        if row.get("format") != "REVENGINSTR.ReceiverCandidateEvidence/1":
            raise MetricProjectionError(f"candidate evidence row {row_number}: unsupported format")
        dimensions = row.get("dimensions")
        if not isinstance(dimensions, dict) or set(dimensions) != set(_RECEIVER_EVIDENCE_DIMENSIONS):
            raise MetricProjectionError(f"candidate evidence row {row_number}: invalid dimensions")
        for name in _RECEIVER_EVIDENCE_DIMENSIONS:
            dimension = dimensions[name]
            if not isinstance(dimension, dict):
                raise MetricProjectionError(f"candidate evidence row {row_number}: invalid {name}")
            status = dimension.get("status")
            evidence_class = dimension.get("evidence_class")
            provenance = dimension.get("provenance")
            if not isinstance(status, str) or status not in _RECEIVER_EVIDENCE_STATES:
                raise MetricProjectionError(f"candidate evidence row {row_number}: invalid {name} status")
            if not isinstance(provenance, list):
                raise MetricProjectionError(f"candidate evidence row {row_number}: invalid {name} provenance")
            if status in {"supported", "contradicted"}:
                if (not isinstance(evidence_class, str) or evidence_class not in _RECEIVER_EVIDENCE_CLASSES
                        or not provenance):
                    raise MetricProjectionError(f"candidate evidence row {row_number}: incomplete {name} evidence")
                if any(not isinstance(item, dict) or not all(
                    isinstance(item.get(field), str) and item[field]
                    for field in ("source_format", "source_id")
                ) for item in provenance):
                    raise MetricProjectionError(f"candidate evidence row {row_number}: invalid {name} provenance")
                evidence_class_counts[name][evidence_class] += 1
            elif evidence_class is not None or provenance:
                raise MetricProjectionError(f"candidate evidence row {row_number}: {name} must not claim evidence")
            status_counts[name][status] += 1
    return {
        "row_count": len(rows),
        "receiver_candidate_evidence": {
            "dimension_metrics": {
                name: {
                    "status_counts": dict(sorted(status_counts[name].items())),
                    "evidence_class_counts": dict(sorted(evidence_class_counts[name].items())),
                }
                for name in _RECEIVER_EVIDENCE_DIMENSIONS
            },
        },
    }


def _validation(report: Any) -> dict[str, Any]:
    if not isinstance(report, dict):
        raise MetricProjectionError("validation report must be a JSON object")
    severity = report.get("severity")
    severity_level = severity.get("level") if isinstance(severity, dict) else None
    intervention = report.get("router_intervention")
    source_corpus = report.get("source_corpus")
    frozen_corpus = report.get("frozen_corpus")
    intervention_fields = (
        "reference_legacy_accept", "reference_changed", "frozen_legacy_accept", "frozen_changed",
    )
    return {
        "row_count": None,
        "validation": {
            "report_format": report.get("format"),
            "labels_available": report.get("labels_available") if isinstance(report.get("labels_available"), bool) else None,
            "reference_rows": (
                report.get("reference_rows") if isinstance(report.get("reference_rows"), int)
                else source_corpus.get("input_rows") if isinstance(source_corpus, dict) and isinstance(source_corpus.get("input_rows"), int)
                else None
            ),
            "frozen_rows": (
                report.get("frozen_rows") if isinstance(report.get("frozen_rows"), int)
                else frozen_corpus.get("rows") if isinstance(frozen_corpus, dict) and isinstance(frozen_corpus.get("rows"), int)
                else None
            ),
            "severity": severity_level if isinstance(severity_level, str) else None,
            "selection": {
                key: source_corpus[key] for key in ("eligible", "eligibility_removed", "excluded_overlap")
                if isinstance(source_corpus, dict) and isinstance(source_corpus.get(key), int)
            } | ({"limit": report["limit"]} if isinstance(report.get("limit"), int) else {}),
            "router_intervention": {
                key: intervention[key] for key in intervention_fields
                if isinstance(intervention, dict) and isinstance(intervention.get(key), int)
            },
        },
    }


def _exact_evidence(actual_path: Path, expected_path: Path, config: dict[str, Any]) -> dict[str, Any]:
    actual_rows = _read_jsonl(actual_path)
    expected_rows = _read_jsonl(expected_path)
    key_fields = config["key_fields"]
    compare_fields = config["compare_fields"]

    def index(rows: list[dict[str, Any]], label: str) -> dict[tuple[Any, ...], dict[str, Any]]:
        indexed: dict[tuple[Any, ...], dict[str, Any]] = {}
        for row_number, row in enumerate(rows, 1):
            if any(field not in row for field in key_fields):
                raise MetricProjectionError(f"{label} row {row_number}: missing exact-evidence key field")
            key = tuple(row[field] for field in key_fields)
            try:
                duplicate = key in indexed
                indexed[key] = row
            except TypeError as exc:
                raise MetricProjectionError(f"{label} row {row_number}: exact-evidence key must be scalar") from exc
            if duplicate:
                raise MetricProjectionError(f"{label}: duplicate exact-evidence key")
        return indexed

    actual = index(actual_rows, "actual")
    expected = index(expected_rows, "expected")
    missing = set(expected) - set(actual)
    unexpected = set(actual) - set(expected)
    common = set(expected) & set(actual)
    for row_number, row in enumerate([*actual_rows, *expected_rows], 1):
        if any(field not in row for field in compare_fields):
            raise MetricProjectionError(f"exact-evidence row {row_number}: missing compared field")
    mismatched = sum(
        any(actual[key][field] != expected[key][field] for field in compare_fields)
        for key in common
    )
    mismatch_rows = mismatched + len(missing) + len(unexpected)
    maximum = config.get("maximum_mismatches", 0)
    return {
        "actual_rows": len(actual_rows), "expected_rows": len(expected_rows),
        "compared_rows": len(common), "mismatched_rows": mismatched,
        "missing_rows": len(missing), "unexpected_rows": len(unexpected),
        "mismatch_rows": mismatch_rows, "maximum_mismatches": maximum,
        "passed": mismatch_rows <= maximum,
    }


def project(config: dict[str, Any], artifact: dict[str, Any], paths: dict[str, Path]) -> dict[str, Any]:
    """Build one projection; only aggregate values are included in its result."""
    kind = config["kind"]
    path = paths[config["artifact"]]
    if kind == "validation":
        if artifact["content"] != "json":
            raise MetricProjectionError("validation projection requires a JSON artifact")
        try:
            projected = _validation(json.loads(path.read_text(encoding="utf-8")))
        except json.JSONDecodeError as exc:
            raise MetricProjectionError(f"invalid validation JSON: {exc}") from exc
    else:
        if artifact["content"] != "jsonl":
            raise MetricProjectionError(f"{kind} projection requires a JSONL artifact")
        rows = _read_jsonl(path)
        if not rows:
            raise MetricProjectionError(f"{kind} projection artifact is empty")
        if kind == "receiver":
            projected = _receiver(rows, config)
        elif kind == "receiver_assessment":
            projected = _receiver_assessment(rows)
        elif kind == "receiver_candidate_evidence":
            projected = _receiver_candidate_evidence(rows)
        else:
            projected = _classification(rows, config)
        if kind == "classifier" and "classification" not in projected:
            raise MetricProjectionError("classifier projection requires truth and prediction fields")
        reason_fields = config.get("reason_fields", {})
        if reason_fields:
            projected["reason_counts"] = {
                category: dict(sorted(Counter(
                    str(row[field]) for row in rows if row.get(field) not in (None, "")
                ).items()))
                for category, field in reason_fields.items()
            }
    exact = config.get("exact_evidence")
    if exact:
        actual_path = paths[exact.get("actual_artifact", config["artifact"])]
        expected_path = paths[exact["expected_artifact"]]
        projected["exact_evidence"] = _exact_evidence(actual_path, expected_path, exact)
    else:
        projected["exact_evidence"] = None
    return {"id": config["id"], "kind": kind, "artifact": config["artifact"], **projected}
