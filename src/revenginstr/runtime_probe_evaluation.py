"""Evaluate bounded runtime probe outcomes on a hash-pinned selected set."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

MANIFEST_FORMAT = "REVENGINSTR.RuntimeProbeEvaluationManifest/1"
PLAN_FORMAT = "REVENGINSTR.EvidenceRequestPlan/1"
OUTCOME_FORMAT = "REVENGINSTR.RuntimeProbeOutcome/1"
REPORT_FORMAT = "REVENGINSTR.RuntimeProbeEvaluation/1"
MAX_REQUESTS = 10_000
MAX_UNCERTAINTY = 1_000
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class ProbeEvaluationError(ValueError):
    """Probe plan and outcomes cannot be evaluated as one bounded set."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _read_json(path: Path, *, jsonl: bool = False) -> tuple[Any, bytes]:
    raw = path.read_bytes()
    if len(raw) > 64 * 1024 * 1024:
        raise ProbeEvaluationError(f"{path}: input exceeds 64 MiB")
    try:
        text = raw.decode("utf-8")
        value = (
            [json.loads(line, object_pairs_hook=_unique_object) for line in text.splitlines() if line.strip()]
            if jsonl else json.loads(text, object_pairs_hook=_unique_object)
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ProbeEvaluationError(f"{path}: invalid JSON: {error}") from error
    return value, raw


def _integer(value: Any, where: str, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise ProbeEvaluationError(f"{where}: expected integer from 0 to {maximum}")
    return value


def _sha256(value: Any, where: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ProbeEvaluationError(f"{where}: expected lowercase SHA-256")
    return value


def evaluate_probe_set(
    manifest: Any, manifest_raw: bytes, plan: Any, plan_raw: bytes,
    outcomes: Any, outcomes_raw: bytes,
) -> dict[str, Any]:
    if not isinstance(manifest, dict) or set(manifest) != {
        "format", "evaluation_id", "plan_sha256", "source_unresolved_set_sha256", "candidates",
    } or manifest.get("format") != MANIFEST_FORMAT:
        raise ProbeEvaluationError("unsupported or malformed probe evaluation manifest")
    evaluation_id = manifest["evaluation_id"]
    if not isinstance(evaluation_id, str) or not evaluation_id.strip() or len(evaluation_id) > 256:
        raise ProbeEvaluationError("manifest: invalid evaluation_id")
    if hashlib.sha256(plan_raw).hexdigest() != _sha256(manifest["plan_sha256"], "manifest plan_sha256"):
        raise ProbeEvaluationError("evidence request plan hash mismatch")
    source_set_hash = _sha256(manifest["source_unresolved_set_sha256"], "manifest source_unresolved_set_sha256")
    if not isinstance(plan, dict) or plan.get("format") != PLAN_FORMAT:
        raise ProbeEvaluationError("expected EvidenceRequestPlan/1")
    source = plan.get("source")
    if not isinstance(source, dict) or _sha256(source.get("candidates_sha256"), "plan source candidates_sha256") != source_set_hash:
        raise ProbeEvaluationError("plan source does not match the declared unresolved set")
    source_count = _integer(source.get("candidate_count"), "plan source candidate_count", 1_000_000)
    if source_count == 0:
        raise ProbeEvaluationError("plan source candidate_count must be positive")
    requests = plan.get("selected_requests")
    if not isinstance(requests, list) or not 1 <= len(requests) <= MAX_REQUESTS:
        raise ProbeEvaluationError("request plan must contain 1 to 10000 selected requests")
    if source_count < len(requests):
        raise ProbeEvaluationError("plan selects more requests than its source candidate set")
    request_by_id: dict[str, dict[str, Any]] = {}
    for row in requests:
        if not isinstance(row, dict):
            raise ProbeEvaluationError("selected request must be an object")
        request_id, cost, bounds = row.get("request_id"), row.get("cost_units"), row.get("bounds")
        if not isinstance(request_id, str) or not request_id.strip() or request_id in request_by_id:
            raise ProbeEvaluationError("selected request ids must be non-empty and unique")
        if row.get("action_type") != "consumer_native_probe":
            raise ProbeEvaluationError(f"request {request_id}: only bounded consumer-native probes are in scope")
        _integer(cost, f"request {request_id} cost_units", 1_000_000)
        if cost == 0 or not isinstance(bounds, dict):
            raise ProbeEvaluationError(f"request {request_id}: missing cost or bounds")
        _integer(bounds.get("max_steps"), f"request {request_id} max_steps", 1_000_000)
        _integer(bounds.get("timeout_ms"), f"request {request_id} timeout_ms", 600_000)
        if bounds["max_steps"] == 0 or bounds["timeout_ms"] == 0:
            raise ProbeEvaluationError(f"request {request_id}: probe bounds must be positive")
        request_by_id[request_id] = row

    candidates = manifest["candidates"]
    if not isinstance(candidates, list) or len(candidates) != len(request_by_id):
        raise ProbeEvaluationError("manifest candidates must cover every selected request exactly once")
    candidate_by_id: dict[str, dict[str, Any]] = {}
    for candidate in candidates:
        if not isinstance(candidate, dict) or set(candidate) != {
            "request_id", "static_prediction", "uncertainty_before_milli", "minimum_narrowing_milli",
        }:
            raise ProbeEvaluationError("evaluation candidate has unexpected fields")
        request_id = candidate["request_id"]
        if not isinstance(request_id, str) or request_id not in request_by_id or request_id in candidate_by_id:
            raise ProbeEvaluationError("evaluation candidates must match unique selected request ids")
        if not isinstance(candidate["static_prediction"], str) or candidate["static_prediction"] not in {"accept", "reject", "unresolved"}:
            raise ProbeEvaluationError(f"candidate {request_id}: invalid static_prediction")
        before = _integer(candidate["uncertainty_before_milli"], f"candidate {request_id} uncertainty_before_milli", MAX_UNCERTAINTY)
        threshold = _integer(candidate["minimum_narrowing_milli"], f"candidate {request_id} minimum_narrowing_milli", MAX_UNCERTAINTY)
        if before == 0 or threshold == 0 or threshold > before:
            raise ProbeEvaluationError(f"candidate {request_id}: invalid uncertainty or narrowing threshold")
        candidate_by_id[request_id] = candidate

    if not isinstance(outcomes, list) or len(outcomes) != len(request_by_id):
        raise ProbeEvaluationError("outcomes must contain exactly one row for every selected request")
    outcome_by_id: dict[str, dict[str, Any]] = {}
    outcome_fields = {
        "format", "evaluation_id", "request_id", "status", "actual_steps", "elapsed_ms",
        "decision", "uncertainty_after_milli", "unlocked_decision_ids",
    }
    for outcome in outcomes:
        if not isinstance(outcome, dict) or set(outcome) != outcome_fields:
            raise ProbeEvaluationError("probe outcome has unexpected fields")
        request_id = outcome["request_id"]
        if (
            outcome["format"] != OUTCOME_FORMAT or outcome["evaluation_id"] != evaluation_id
            or not isinstance(request_id, str) or request_id not in request_by_id or request_id in outcome_by_id
        ):
            raise ProbeEvaluationError("outcome format, evaluation id, or request id mismatch")
        request = request_by_id[request_id]
        if not isinstance(request.get("subject_id"), str) or not request["subject_id"].strip():
            raise ProbeEvaluationError(f"request {request_id}: invalid subject_id")
        steps = _integer(outcome["actual_steps"], f"outcome {request_id} actual_steps", 1_000_000)
        elapsed = _integer(outcome["elapsed_ms"], f"outcome {request_id} elapsed_ms", 600_000)
        if steps > request["bounds"]["max_steps"] or elapsed > request["bounds"]["timeout_ms"]:
            raise ProbeEvaluationError(f"outcome {request_id}: consumer exceeded declared probe bounds")
        ids = outcome["unlocked_decision_ids"]
        if (
            not isinstance(ids, list) or len(ids) > 10_000
            or any(not isinstance(item, str) or not item.strip() for item in ids)
            or len(set(ids)) != len(ids)
        ):
            raise ProbeEvaluationError(f"outcome {request_id}: invalid unlocked_decision_ids")
        if outcome["status"] == "completed":
            if not isinstance(outcome["decision"], str) or outcome["decision"] not in {"accept", "reject", "unresolved"}:
                raise ProbeEvaluationError(f"outcome {request_id}: invalid completed decision")
            _integer(outcome["uncertainty_after_milli"], f"outcome {request_id} uncertainty_after_milli", MAX_UNCERTAINTY)
        elif outcome["status"] == "incomplete":
            if outcome["decision"] is not None or outcome["uncertainty_after_milli"] is not None or ids:
                raise ProbeEvaluationError(f"outcome {request_id}: incomplete probe cannot claim a result")
        else:
            raise ProbeEvaluationError(f"outcome {request_id}: status must be completed or incomplete")
        outcome_by_id[request_id] = outcome

    report_rows = []
    completed = decisive = total_reduction = total_steps = total_elapsed = 0
    total_requested_units = sum(request["cost_units"] for request in requests)
    disagreements = comparable = 0
    unlocked: set[str] = set()
    for request_id, request in request_by_id.items():
        candidate, outcome = candidate_by_id[request_id], outcome_by_id[request_id]
        reduction = None
        reason = "incomplete"
        disagreement = None
        total_steps += outcome["actual_steps"]
        total_elapsed += outcome["elapsed_ms"]
        if outcome["status"] == "completed":
            completed += 1
            reduction = candidate["uncertainty_before_milli"] - outcome["uncertainty_after_milli"]
            total_reduction += reduction
            prediction, decision = candidate["static_prediction"], outcome["decision"]
            if prediction in {"accept", "reject"} and decision in {"accept", "reject"}:
                comparable += 1
                disagreement = prediction != decision
                disagreements += disagreement
            if decision in {"accept", "reject"}:
                decisive += 1
                reason = decision
            elif reduction >= candidate["minimum_narrowing_milli"]:
                decisive += 1
                reason = "material_uncertainty_reduction"
            else:
                reason = "not_decisive"
            unlocked.update(outcome["unlocked_decision_ids"])
        report_rows.append({
            "request_id": request_id,
            "subject_id": request["subject_id"],
            "requested_cost_units": request["cost_units"],
            "status": outcome["status"],
            "actual_steps": outcome["actual_steps"],
            "elapsed_ms": outcome["elapsed_ms"],
            "uncertainty_before_milli": candidate["uncertainty_before_milli"],
            "uncertainty_after_milli": outcome["uncertainty_after_milli"],
            "uncertainty_reduction_milli": reduction,
            "decision": outcome["decision"],
            "decisive_reason": reason,
            "static_prediction": candidate["static_prediction"],
            "static_disagreement": disagreement,
            "unlocked_decision_ids": outcome["unlocked_decision_ids"],
        })
    def rate(numerator: int, denominator: int) -> int | None:
        return numerator * 1_000_000 // denominator if denominator else None

    report = {
        "format": REPORT_FORMAT,
        "evaluation_id": evaluation_id,
        "plan_sha256": hashlib.sha256(plan_raw).hexdigest(),
        "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "outcomes_sha256": hashlib.sha256(outcomes_raw).hexdigest(),
        "source_unresolved_set_sha256": manifest["source_unresolved_set_sha256"],
        "metrics": {
            "planned_request_count": len(requests),
            "completed_count": completed,
            "incomplete_count": len(requests) - completed,
            "completion_rate_ppm": rate(completed, len(requests)),
            "requested_cost_units_total": total_requested_units,
            "requested_cost_units_per_decisive_result_milli": total_requested_units * 1_000 // decisive if decisive else None,
            "actual_steps_total": total_steps,
            "elapsed_ms_total": total_elapsed,
            "decisive_count": decisive,
            "decisive_rate_of_completed_ppm": rate(decisive, completed),
            "uncertainty_reduction_total_milli": total_reduction,
            "uncertainty_reduction_mean_milli": total_reduction // completed if completed else None,
            "unlocked_decision_count": len(unlocked),
            "unlocked_decision_ids": sorted(unlocked),
            "disagreement_comparable_count": comparable,
            "static_disagreement_count": disagreements,
            "static_disagreement_rate_ppm": rate(disagreements, comparable),
        },
        "results": report_rows,
        "scope_note": "Caller-provided freeze hashes are provenance labels; this report cannot verify that the set was frozen before outcomes were observed.",
    }
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("request_plan", type=Path)
    parser.add_argument("outcomes", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    inputs = {path.resolve() for path in (args.manifest, args.request_plan, args.outcomes)}
    if args.output.resolve() in inputs:
        raise ProbeEvaluationError("output path must not replace an input")
    manifest, manifest_raw = _read_json(args.manifest)
    plan, plan_raw = _read_json(args.request_plan)
    outcomes, outcomes_raw = _read_json(args.outcomes, jsonl=True)
    report = evaluate_probe_set(manifest, manifest_raw, plan, plan_raw, outcomes, outcomes_raw)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    metrics = report["metrics"]
    print("completed:", metrics["completed_count"], "/", metrics["planned_request_count"])
    print("decisive:", metrics["decisive_count"])
    print("requested cost units:", metrics["requested_cost_units_total"])
    print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
