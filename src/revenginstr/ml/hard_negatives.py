"""Retain selected mistakes from a family-disjoint evaluation for review."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
from typing import Any

from revenginstr.ml import SELECTIVE_CLASSIFIER_FORMAT
from revenginstr.ml.selective import read_jsonl

FORMAT = "REVENGINSTR.ClassifierHardNegativeSet/1"
EVALUATION_FORMAT = "REVENGINSTR.SelectiveThresholdEvaluation/1"
ROUTE_ACTIONS = ("accept", "review", "escalate")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_hard_negative_set(
    evaluation_report: dict[str, Any],
    rows: list[dict[str, Any]],
    *,
    minimum_confidence: float,
    actions: list[str],
    evaluation_report_sha256: str,
    predictions_sha256: str,
) -> dict[str, Any]:
    if isinstance(minimum_confidence, bool) or not isinstance(minimum_confidence, (int, float)):
        raise ValueError("minimum_confidence must be a finite number in [0, 1]")
    try:
        minimum_confidence = float(minimum_confidence)
    except OverflowError as exc:
        raise ValueError("minimum_confidence must be a finite number in [0, 1]") from exc
    if not math.isfinite(minimum_confidence) or not 0.0 <= minimum_confidence <= 1.0:
        raise ValueError("minimum_confidence must be a finite number in [0, 1]")
    if not isinstance(actions, list) or any(not isinstance(action, str) for action in actions):
        raise ValueError("actions must contain one or more supported route actions")
    selected_actions = tuple(dict.fromkeys(actions))
    if not selected_actions or any(action not in ROUTE_ACTIONS for action in selected_actions):
        raise ValueError("actions must contain one or more supported route actions")
    if not all(
        isinstance(value, str) and len(value) == 64
        and all(character in "0123456789abcdefABCDEF" for character in value)
        for value in (evaluation_report_sha256, predictions_sha256)
    ):
        raise ValueError("input provenance must contain SHA-256 digests")
    if not isinstance(evaluation_report, dict) or evaluation_report.get("format") != EVALUATION_FORMAT:
        raise ValueError("unsupported threshold evaluation report format")
    source = evaluation_report.get("source")
    classes = evaluation_report.get("classes")
    if (
        not isinstance(source, dict)
        or source.get("family_disjoint") is not True
        or source.get("classifier_format") != SELECTIVE_CLASSIFIER_FORMAT
        or source.get("evaluation_predictions_sha256") != predictions_sha256
        or not isinstance(classes, dict)
        or len(classes) < 2
        or any(not isinstance(label, str) or not label for label in classes)
    ):
        raise ValueError("evaluation report does not match a family-disjoint prediction input")
    for field in ("evaluation_rows", "evaluation_families"):
        value = source.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise ValueError("evaluation report has invalid population counts")
    if not rows:
        raise ValueError("evaluation predictions must not be empty")

    allowed = set(classes)
    seen_ids: set[str] = set()
    families: set[str] = set()
    selected: list[dict[str, Any]] = []
    for line_no, row in enumerate(rows, 1):
        if not isinstance(row, dict) or row.get("format") != SELECTIVE_CLASSIFIER_FORMAT:
            raise ValueError(f"evaluation row {line_no}: unsupported format")
        record_id, family_id = row.get("id"), row.get("family_id")
        truth, prediction, correct = row.get("truth"), row.get("prediction"), row.get("correct")
        confidence, action = row.get("confidence"), row.get("action")
        if not isinstance(record_id, str) or not record_id or record_id in seen_ids:
            raise ValueError(f"evaluation row {line_no}: invalid or duplicate id")
        if not isinstance(family_id, str) or not family_id:
            raise ValueError(f"evaluation row {line_no}: invalid family_id")
        if not isinstance(truth, str) or truth not in allowed or not isinstance(prediction, str) or prediction not in allowed:
            raise ValueError(f"evaluation row {line_no}: truth or prediction outside evaluated classes")
        if not isinstance(correct, bool) or correct != (truth == prediction):
            raise ValueError(f"evaluation row {line_no}: correct flag disagrees with labels")
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
        if not correct and confidence >= minimum_confidence and action in selected_actions:
            selected.append({
                "id": record_id,
                "family_id": family_id,
                "truth": truth,
                "prediction": prediction,
                "confidence": confidence,
                "action": action,
            })

    if len(rows) != source["evaluation_rows"] or len(families) != source["evaluation_families"]:
        raise ValueError("evaluation population counts disagree with threshold report")
    return {
        "format": FORMAT,
        "source": {
            "evaluation_report_sha256": evaluation_report_sha256,
            "evaluation_predictions_sha256": predictions_sha256,
            "evaluation_rows": len(rows),
            "evaluation_families": len(families),
            "family_disjoint": True,
        },
        "selection": {
            "minimum_confidence": minimum_confidence,
            "actions": list(selected_actions),
            "selected_rows": len(selected),
            "selected_families": len({row["family_id"] for row in selected}),
        },
        "examples": selected,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("threshold_evaluation_json", type=Path)
    parser.add_argument("evaluation_predictions_jsonl", type=Path)
    parser.add_argument("--minimum-confidence", type=float, default=0.9)
    parser.add_argument("--action", choices=ROUTE_ACTIONS, action="append", dest="actions")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    report_bytes = args.threshold_evaluation_json.read_bytes()
    result = build_hard_negative_set(
        json.loads(report_bytes),
        list(read_jsonl(args.evaluation_predictions_jsonl)),
        minimum_confidence=args.minimum_confidence,
        actions=args.actions or ["accept"],
        evaluation_report_sha256=hashlib.sha256(report_bytes).hexdigest(),
        predictions_sha256=_sha256(args.evaluation_predictions_jsonl),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("evaluation rows:", result["source"]["evaluation_rows"])
    print("retained hard negatives:", result["selection"]["selected_rows"])
    print("output:", args.output)
    return 0
