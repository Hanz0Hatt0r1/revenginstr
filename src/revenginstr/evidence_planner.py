"""Prioritize caller-approved, bounded evidence requests without executing them."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any

CANDIDATES_FORMAT = "REVENGINSTR.EvidenceRequestCandidates/1"
PLAN_FORMAT = "REVENGINSTR.EvidenceRequestPlan/1"
ACTION_TYPES = {
    "function_slice", "callers_callees", "field_store_recovery",
    "constructor_vtable_anchor", "consumer_native_probe", "family_example", "human_review",
}
SUBJECT_KINDS = {"function", "family", "dispatch", "claim"}
RATIONALE_CODES = {
    "unresolved_dispatch", "missing_receiver_provenance", "field_flow_gap",
    "out_of_distribution", "evidence_conflict", "high_downstream_leverage", "human_requested",
}
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_BOUNDS = {"max_depth": 8, "max_items": 10000, "max_steps": 1000000, "timeout_ms": 600000}


def _nonempty_id(value: Any, where: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ValueError(f"{where}: expected a non-empty identifier")
    return value


def _number(value: Any, where: str, *, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{where}: expected a number")
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError) as error:
        raise ValueError(f"{where}: expected a finite number") from error
    if not math.isfinite(number) or not minimum <= number <= maximum:
        raise ValueError(f"{where}: value is outside [{minimum}, {maximum}]")
    return number


def _validate_bounds(action_type: str, value: Any, where: str) -> dict[str, int]:
    if not isinstance(value, dict) or not value or set(value) - _BOUNDS.keys():
        raise ValueError(f"{where}: bounds must contain at least one supported finite limit")
    bounds = {}
    for name, maximum in _BOUNDS.items():
        if name not in value:
            continue
        limit = value[name]
        minimum = 1
        if isinstance(limit, bool) or not isinstance(limit, int) or not minimum <= limit <= maximum:
            raise ValueError(f"{where}: invalid {name}")
        bounds[name] = limit

    required = {
        "function_slice": {"max_items"},
        "callers_callees": {"max_depth", "max_items"},
        "field_store_recovery": {"max_items"},
        "constructor_vtable_anchor": {"max_items"},
        "consumer_native_probe": {"max_steps", "timeout_ms"},
        "family_example": {"max_items"},
        "human_review": {"max_items"},
    }[action_type]
    if not required.issubset(bounds):
        raise ValueError(f"{where}: {action_type} requires bounds {sorted(required)}")
    if action_type == "human_review" and bounds["max_items"] != 1:
        raise ValueError(f"{where}: human_review must be bounded to one item")
    return bounds


def _validate_candidates(candidates: Any) -> list[dict[str, Any]]:
    if (
        not isinstance(candidates, dict)
        or set(candidates) != {"format", "candidates"}
        or candidates.get("format") != CANDIDATES_FORMAT
        or not isinstance(candidates.get("candidates"), list)
        or not candidates["candidates"]
    ):
        raise ValueError("unsupported evidence request candidates format or empty candidate list")
    rows = []
    request_ids: set[str] = set()
    subject_kinds: dict[str, str] = {}
    for index, row in enumerate(candidates["candidates"], 1):
        where = f"candidate {index}"
        fields = {
            "request_id", "subject_id", "subject_kind", "action_type", "bounds",
            "cost_units", "expected_uncertainty_reduction", "downstream_leverage",
            "rationale_codes", "approval_status", "approval_sha256",
        }
        if not isinstance(row, dict) or set(row) != fields:
            raise ValueError(f"{where}: unexpected fields")
        request_id = _nonempty_id(row["request_id"], f"{where} request_id")
        subject_id = _nonempty_id(row["subject_id"], f"{where} subject_id")
        if request_id in request_ids:
            raise ValueError(f"{where}: duplicate request_id")
        request_ids.add(request_id)
        if not isinstance(row["subject_kind"], str) or row["subject_kind"] not in SUBJECT_KINDS:
            raise ValueError(f"{where}: unsupported subject_kind")
        if subject_id in subject_kinds and subject_kinds[subject_id] != row["subject_kind"]:
            raise ValueError(f"{where}: subject_id maps to multiple subject kinds")
        subject_kinds[subject_id] = row["subject_kind"]
        action_type = row["action_type"]
        if not isinstance(action_type, str) or action_type not in ACTION_TYPES:
            raise ValueError(f"{where}: unsupported action_type")
        bounds = _validate_bounds(action_type, row["bounds"], f"{where} bounds")
        cost = row["cost_units"]
        if isinstance(cost, bool) or not isinstance(cost, int) or not 1 <= cost <= 1000000:
            raise ValueError(f"{where}: cost_units must be between 1 and 1000000")
        reduction = _number(
            row["expected_uncertainty_reduction"], f"{where} expected_uncertainty_reduction",
            minimum=0.000001, maximum=1.0,
        )
        leverage = _number(row["downstream_leverage"], f"{where} downstream_leverage", minimum=0.000001, maximum=1000.0)
        reasons = row["rationale_codes"]
        if (
            not isinstance(reasons, list) or not reasons
            or any(not isinstance(reason, str) for reason in reasons)
            or len(reasons) != len(set(reasons))
            or not set(reasons) <= RATIONALE_CODES
        ):
            raise ValueError(f"{where}: invalid rationale_codes")
        if row["approval_status"] != "approved":
            raise ValueError(f"{where}: evidence request must be explicitly approved")
        if not isinstance(row["approval_sha256"], str) or _SHA256.fullmatch(row["approval_sha256"]) is None:
            raise ValueError(f"{where}: invalid approval SHA-256")
        rows.append({
            "request_id": request_id,
            "subject_id": subject_id,
            "subject_kind": row["subject_kind"],
            "action_type": action_type,
            "bounds": bounds,
            "cost_units": cost,
            "expected_uncertainty_reduction": reduction,
            "downstream_leverage": leverage,
            "rationale_codes": sorted(reasons),
            "approval_status": "approved",
            "approval_sha256": row["approval_sha256"],
            "priority_score": leverage * reduction / cost,
        })
    return rows


def build_evidence_request_plan(
    candidates: dict[str, Any],
    *,
    candidates_sha256: str,
    budget_units: int,
    max_requests: int,
) -> dict[str, Any]:
    """Select one approved bounded request per subject under a fixed budget."""
    if not isinstance(candidates_sha256, str) or _SHA256.fullmatch(candidates_sha256) is None:
        raise ValueError("invalid candidates SHA-256")
    if isinstance(budget_units, bool) or not isinstance(budget_units, int) or not 1 <= budget_units <= 1000000:
        raise ValueError("budget_units must be between 1 and 1000000")
    if isinstance(max_requests, bool) or not isinstance(max_requests, int) or not 1 <= max_requests <= 10000:
        raise ValueError("max_requests must be between 1 and 10000")

    rows = _validate_candidates(candidates)
    ranked = sorted(rows, key=lambda row: (-row["priority_score"], row["request_id"]))
    selected = []
    selected_subjects: set[str] = set()
    spent = 0
    deferred = Counter({"subject_already_selected": 0, "over_budget": 0, "request_limit": 0})
    for row in ranked:
        if len(selected) >= max_requests:
            deferred["request_limit"] += 1
            continue
        if row["subject_id"] in selected_subjects:
            deferred["subject_already_selected"] += 1
            continue
        if spent + row["cost_units"] > budget_units:
            deferred["over_budget"] += 1
            continue
        selected_subjects.add(row["subject_id"])
        spent += row["cost_units"]
        selected.append({
            key: row[key] for key in (
                "request_id", "subject_id", "subject_kind", "action_type", "bounds",
                "cost_units", "expected_uncertainty_reduction", "downstream_leverage",
                "priority_score", "rationale_codes", "approval_status", "approval_sha256",
            )
        })

    return {
        "format": PLAN_FORMAT,
        "source": {"candidates_sha256": candidates_sha256, "candidate_count": len(rows)},
        "budget_units": budget_units,
        "spent_units": spent,
        "remaining_units": budget_units - spent,
        "max_requests": max_requests,
        "selected_requests": selected,
        "deferred_counts": dict(deferred),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("candidates_json", type=Path)
    parser.add_argument("--budget-units", type=int, required=True)
    parser.add_argument("--max-requests", type=int, default=100)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    raw = args.candidates_json.read_bytes()
    candidates = json.loads(raw)
    plan = build_evidence_request_plan(
        candidates,
        candidates_sha256=hashlib.sha256(raw).hexdigest(),
        budget_units=args.budget_units,
        max_requests=args.max_requests,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("candidates:", plan["source"]["candidate_count"])
    print("selected:", len(plan["selected_requests"]))
    print("spent units:", plan["spent_units"])
    print("output:", args.output)
    return 0
