"""Group family-held-out classifier errors by confusion pair and route action."""
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

FORMAT = "REVENGINSTR.ClassifierErrorBuckets/1"
ROUTE_ACTIONS = ("accept", "review", "escalate")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_error_buckets(
    evaluation_report: dict[str, Any],
    rows: list[dict[str, Any]],
    *,
    evaluation_report_sha256: str,
    predictions_sha256: str,
) -> dict[str, Any]:
    if not isinstance(evaluation_report, dict) or evaluation_report.get("format") != (
        "REVENGINSTR.SelectiveThresholdEvaluation/1"
    ):
        raise ValueError("unsupported threshold evaluation report format")
    source = evaluation_report.get("source")
    classes = evaluation_report.get("classes")
    if (
        not isinstance(source, dict) or source.get("family_disjoint") is not True
        or not isinstance(classes, dict) or len(classes) < 2
        or source.get("classifier_format") != SELECTIVE_CLASSIFIER_FORMAT
        or source.get("evaluation_predictions_sha256") != predictions_sha256
        or any(not isinstance(label, str) or not label for label in classes)
    ):
        raise ValueError("evaluation report does not match a family-disjoint prediction input")
    if any(
        isinstance(source.get(field), bool)
        or not isinstance(source.get(field), int)
        or source[field] < 1
        for field in ("evaluation_rows", "evaluation_families")
    ):
        raise ValueError("evaluation report has invalid population counts")
    if not rows:
        raise ValueError("evaluation predictions must not be empty")

    allowed = set(classes)
    seen_ids: set[str] = set()
    families: set[str] = set()
    buckets: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    error_count = accepted_error_count = 0
    for line_no, row in enumerate(rows, 1):
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
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError(f"evaluation row {line_no}: invalid calibrated confidence") from exc
        if not math.isfinite(confidence) or not 0.0 <= confidence <= 1.0:
            raise ValueError(f"evaluation row {line_no}: invalid calibrated confidence")
        if action not in ROUTE_ACTIONS:
            raise ValueError(f"evaluation row {line_no}: invalid route action")
        seen_ids.add(record_id)
        families.add(family_id)
        if not correct:
            buckets[(truth, prediction)].append({
                "family_id": family_id, "action": action, "confidence": confidence,
            })
            error_count += 1
            accepted_error_count += action == "accept"

    if len(rows) != source.get("evaluation_rows") or len(families) != source.get("evaluation_families"):
        raise ValueError("evaluation population counts disagree with threshold report")

    error_buckets = []
    for (truth, prediction), errors in sorted(
        buckets.items(), key=lambda item: (-len(item[1]), item[0])
    ):
        actions = Counter(row["action"] for row in errors)
        confidences = [row["confidence"] for row in errors]
        error_buckets.append({
            "truth": truth,
            "prediction": prediction,
            "error_count": len(errors),
            "family_count": len({row["family_id"] for row in errors}),
            "accepted_error_count": actions["accept"],
            "action_counts": {action: actions[action] for action in ROUTE_ACTIONS},
            "confidence": {
                "count": len(confidences),
                "mean": sum(confidences) / len(confidences),
                "minimum": min(confidences),
                "maximum": max(confidences),
            },
        })
    return {
        "format": FORMAT,
        "source": {
            "evaluation_report_sha256": evaluation_report_sha256,
            "evaluation_predictions_sha256": predictions_sha256,
            "evaluation_rows": len(rows),
            "evaluation_families": len(families),
            "family_disjoint": True,
        },
        "error_rows": error_count,
        "error_rate": error_count / len(rows),
        "accepted_error_rows": accepted_error_count,
        "error_buckets": error_buckets,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("threshold_evaluation_json", type=Path)
    parser.add_argument("evaluation_predictions_jsonl", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    report_bytes = args.threshold_evaluation_json.read_bytes()
    report = json.loads(report_bytes)
    rows = list(read_jsonl(args.evaluation_predictions_jsonl))
    result = build_error_buckets(
        report,
        rows,
        evaluation_report_sha256=hashlib.sha256(report_bytes).hexdigest(),
        predictions_sha256=_sha256(args.evaluation_predictions_jsonl),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("evaluation rows:", result["source"]["evaluation_rows"])
    print("errors:", result["error_rows"])
    print("confusion-pair buckets:", len(result["error_buckets"]))
    print("accepted errors:", result["accepted_error_rows"])
    print("output:", args.output)
    return 0
