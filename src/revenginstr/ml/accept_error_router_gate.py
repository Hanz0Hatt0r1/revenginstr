"""Evaluate an accept-only router on a frozen labeled holdout."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from .accept_error_router import FORMAT as ROUTER_FORMAT
from .accept_error_router import identity_sha256, read_jsonl, sha256_file

FORMAT = "REVENGINSTR.FrozenAcceptRouterGate/1"
POPULATIONS = {"in_distribution", "ood"}
ACTIONS = {"accept", "review", "escalate"}


def _number(value: Any, name: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be numeric")
    result = float(value)
    if not 0.0 <= result <= 1.0:
        raise ValueError(f"{name} must be in [0, 1]")
    return result


def _read_manifest(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected JSON object")
    return value


def _check_rows(rows: list[dict[str, Any]]) -> None:
    if not rows:
        raise ValueError("frozen gate population is empty")
    required = (
        "id", "family_id", "truth", "prediction", "base_action", "action",
        "accept_error_router_format", "accept_error_router_reason",
        "accept_correctness_probability", "critical_case",
        "evidence_conflict_detected", "population", "external_evidence_present",
    )
    for index, row in enumerate(rows, 1):
        missing = [key for key in required if key not in row]
        if missing:
            raise ValueError(f"gate row {index} missing fields: {missing}")
        for key in ("id", "family_id", "truth", "prediction"):
            if not isinstance(row[key], str) or not row[key]:
                raise ValueError(f"gate row {index} has invalid {key}")
        if row["accept_error_router_format"] != ROUTER_FORMAT:
            raise ValueError(f"gate row {index} has incompatible router format")
        if row["base_action"] not in ACTIONS or row["action"] not in ACTIONS:
            raise ValueError(f"gate row {index} has invalid action")
        if row["population"] not in POPULATIONS:
            raise ValueError(f"gate row {index} has invalid population")
        for key in ("critical_case", "evidence_conflict_detected", "external_evidence_present"):
            if not isinstance(row[key], bool):
                raise ValueError(f"gate row {index} {key} must be boolean")


def _group_metrics(rows: list[dict[str, Any]], key: str) -> dict[str, Any]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        value = row[key]
        group = str(value).lower() if isinstance(value, bool) else str(value)
        groups.setdefault(group, []).append(row)
    report: dict[str, Any] = {}
    for name, members in sorted(groups.items()):
        accepted = [row for row in members if row["action"] == "accept"]
        correct = sum(row["prediction"] == row["truth"] for row in accepted)
        report[name] = {
            "rows": len(members),
            "accepted": len(accepted),
            "correct_accepts": correct,
            "accepted_precision": correct / len(accepted) if accepted else None,
            "coverage": len(accepted) / len(members),
        }
    return report


def evaluate_gate(
    routed_path: Path,
    router_manifest_path: Path,
    training_oof_path: Path,
    *,
    min_precision: float = 0.97,
    min_coverage: float = 0.55,
    max_critical_false_accept_rate: float = 0.01,
) -> dict[str, Any]:
    for value, name in (
        (min_precision, "min_precision"),
        (min_coverage, "min_coverage"),
        (max_critical_false_accept_rate, "max_critical_false_accept_rate"),
    ):
        if not 0.0 <= value <= 1.0:
            raise ValueError(f"{name} must be in [0, 1]")

    router = _read_manifest(router_manifest_path)
    if router.get("format") != ROUTER_FORMAT:
        raise ValueError(f"router manifest format must be {ROUTER_FORMAT}")
    policy = router.get("policy")
    if not isinstance(policy, dict) or not (
        policy.get("scope") == "base_accept_only"
        and policy.get("below_threshold_action") == "escalate"
        and policy.get("non_accept_action") == "preserve"
        and policy.get("class_prediction_action") == "preserve"
        and policy.get("promotions_allowed") is False
    ):
        raise ValueError("router manifest does not declare the accept-only monotone policy")
    threshold = _number(router.get("threshold"), "router threshold")
    source = router.get("source")
    if not isinstance(source, dict):
        raise ValueError("router manifest has no hash-bound training source")

    training_rows = read_jsonl(training_oof_path)
    training_ids = {str(row["id"]) for row in training_rows}
    training_families: set[str] = set()
    for row in training_rows:
        family = row.get("family_id")
        if not isinstance(family, str) or not family:
            raise ValueError("training OOF row missing family_id")
        training_families.add(family)
    training_sha = sha256_file(training_oof_path)
    if source.get("base_oof_sha256") != training_sha:
        raise ValueError("training OOF hash does not match router manifest source")
    if source.get("base_oof_rows") != len(training_rows):
        raise ValueError("training OOF row count does not match router manifest source")
    if source.get("base_oof_id_sha256") != identity_sha256(list(training_ids)):
        raise ValueError("training OOF identity digest does not match router manifest source")
    if source.get("base_oof_family_sha256") != identity_sha256(list(training_families)):
        raise ValueError("training OOF family digest does not match router manifest source")

    rows = read_jsonl(routed_path)
    _check_rows(rows)
    gate_ids = {str(row["id"]) for row in rows}
    gate_families = {str(row["family_id"]) for row in rows}
    identity_overlap = len(training_ids & gate_ids)
    family_overlap = len(training_families & gate_families)

    invalid_policy_rows = 0
    threshold_branch_mismatches = 0
    for row in rows:
        base_action = row["base_action"]
        action = row["action"]
        reason = row["accept_error_router_reason"]
        score = row["accept_correctness_probability"]
        if base_action != "accept":
            valid = action == base_action and score is None and reason == "base_action_preserved"
        else:
            score = _number(score, "accept correctness probability")
            expected_action = "accept" if score >= threshold else "escalate"
            expected_reason = (
                "accept_score_at_or_above_threshold"
                if score >= threshold else "accept_score_below_threshold"
            )
            valid = action == expected_action and reason == expected_reason
            threshold_branch_mismatches += int(not valid)
        invalid_policy_rows += int(not valid)

    accepted = [row for row in rows if row["action"] == "accept"]
    correct_accepts = sum(row["prediction"] == row["truth"] for row in accepted)
    critical_rows = [row for row in rows if row["critical_case"]]
    critical_false_accepts = sum(
        row["action"] == "accept" and row["prediction"] != row["truth"]
        for row in critical_rows
    )
    conflicts = [row for row in rows if row["evidence_conflict_detected"]]
    conflict_accepts = sum(row["action"] == "accept" for row in conflicts)
    precision = correct_accepts / len(accepted) if accepted else None
    coverage = len(accepted) / len(rows)
    critical_rate = critical_false_accepts / len(critical_rows) if critical_rows else None
    checks = {
        "router_source_matches_training_oof": True,
        "training_and_gate_ids_disjoint": identity_overlap == 0,
        "training_and_gate_families_disjoint": family_overlap == 0,
        "threshold_branch_and_monotone_policy_valid": invalid_policy_rows == 0,
        "critical_subset_available": bool(critical_rows),
        "evidence_conflicts_never_accept": conflict_accepts == 0,
        "accepted_precision_meets_minimum": precision is not None and precision >= min_precision,
        "coverage_meets_minimum": coverage >= min_coverage,
        "critical_false_accept_rate_below_maximum": (
            critical_rate is not None and critical_rate < max_critical_false_accept_rate
        ),
    }
    return {
        "format": FORMAT,
        "router_format": ROUTER_FORMAT,
        "provenance": {
            "routed_input_sha256": sha256_file(routed_path),
            "router_manifest_sha256": sha256_file(router_manifest_path),
            "training_oof_sha256": training_sha,
            "gate_id_sha256": identity_sha256(list(gate_ids)),
            "gate_family_sha256": identity_sha256(list(gate_families)),
            "training_rows": len(training_rows),
            "training_id_count": len(training_ids),
            "training_family_count": len(training_families),
            "gate_rows": len(rows),
            "gate_id_count": len(gate_ids),
            "gate_family_count": len(gate_families),
            "training_gate_id_overlap": identity_overlap,
            "training_gate_family_overlap": family_overlap,
        },
        "minimums": {
            "accepted_precision": min_precision,
            "coverage": min_coverage,
            "critical_false_accept_rate_exclusive_maximum": max_critical_false_accept_rate,
        },
        "router_threshold": threshold,
        "metrics": {
            "rows": len(rows),
            "base_accepts": sum(row["base_action"] == "accept" for row in rows),
            "accepted": len(accepted),
            "correct_accepts": correct_accepts,
            "incorrect_accepts": len(accepted) - correct_accepts,
            "accepted_precision": precision,
            "coverage": coverage,
            "critical_rows": len(critical_rows),
            "critical_false_accepts": critical_false_accepts,
            "critical_false_accept_rate": critical_rate,
            "evidence_conflicts": len(conflicts),
            "evidence_conflict_accepts": conflict_accepts,
            "policy_violation_rows": invalid_policy_rows,
            "threshold_branch_mismatches": threshold_branch_mismatches,
        },
        "coverage_by_predicted_class": _group_metrics(rows, "prediction"),
        "coverage_by_population": _group_metrics(rows, "population"),
        "coverage_by_external_evidence": _group_metrics(rows, "external_evidence_present"),
        "checks": checks,
        "gate_pass": all(checks.values()),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("routed_predictions", type=Path)
    parser.add_argument("router_manifest", type=Path)
    parser.add_argument("training_oof", type=Path)
    parser.add_argument("--min-precision", type=float, default=0.97)
    parser.add_argument("--min-coverage", type=float, default=0.55)
    parser.add_argument("--max-critical-false-accept-rate", type=float, default=0.01)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args(argv)
    report = evaluate_gate(
        args.routed_predictions,
        args.router_manifest,
        args.training_oof,
        min_precision=args.min_precision,
        min_coverage=args.min_coverage,
        max_critical_false_accept_rate=args.max_critical_false_accept_rate,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("format:", FORMAT)
    print("rows:", report["metrics"]["rows"])
    print("accepted precision:", report["metrics"]["accepted_precision"])
    print("coverage:", report["metrics"]["coverage"])
    print("critical false-accept rate:", report["metrics"]["critical_false_accept_rate"])
    print("evidence conflict accepts:", report["metrics"]["evidence_conflict_accepts"])
    print("gate pass:", report["gate_pass"])
    print("output:", args.output)
    if args.strict and not report["gate_pass"]:
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
