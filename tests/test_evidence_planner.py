from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.evidence_planner import ACTION_TYPES, CANDIDATES_FORMAT, PLAN_FORMAT, PROBE_KINDS, build_evidence_request_plan, main

ROOT = Path(__file__).resolve().parents[1]
CANDIDATES_SCHEMA = json.loads((ROOT / "schemas/evidence-request-candidates-v1.schema.json").read_text(encoding="utf-8"))
PLAN_SCHEMA = json.loads((ROOT / "schemas/evidence-request-plan-v1.schema.json").read_text(encoding="utf-8"))


def candidate(
    request_id: str,
    subject_id: str,
    *,
    action: str = "function_slice",
    cost: int = 1,
    uncertainty: float = 0.5,
    leverage: float = 1.0,
    probe_kind: str | None = None,
) -> dict:
    bounds = {"max_items": 20}
    if action == "callers_callees":
        bounds = {"max_depth": 2, "max_items": 20}
    elif action == "consumer_native_probe":
        bounds = {"max_steps": 100, "timeout_ms": 5000}
    elif action == "human_review":
        bounds = {"max_items": 1}
    row = {
        "request_id": request_id,
        "subject_id": subject_id,
        "subject_kind": "function",
        "action_type": action,
        "bounds": bounds,
        "cost_units": cost,
        "expected_uncertainty_reduction": uncertainty,
        "downstream_leverage": leverage,
        "rationale_codes": ["unresolved_dispatch"],
        "approval_status": "approved",
        "approval_sha256": "a" * 64,
    }
    if probe_kind is not None:
        row["probe_kind"] = probe_kind
    return row


def fixture() -> dict:
    return {
        "format": CANDIDATES_FORMAT,
        "candidates": [
            candidate("request-high", "subject-a", cost=4, uncertainty=0.8, leverage=8.0),
            candidate("request-alt", "subject-a", cost=1, uncertainty=0.9, leverage=1.0),
            candidate("request-mid", "subject-b", cost=1, uncertainty=0.5, leverage=2.0),
            candidate("request-costly", "subject-c", cost=3, uncertainty=0.5, leverage=3.0),
        ],
    }


def test_evidence_request_plan_selects_approved_actions_by_value_per_cost() -> None:
    candidates = fixture()
    report = build_evidence_request_plan(
        candidates,
        candidates_sha256="b" * 64,
        budget_units=5,
        max_requests=4,
    )

    Draft202012Validator.check_schema(CANDIDATES_SCHEMA)
    Draft202012Validator(CANDIDATES_SCHEMA).validate(candidates)
    Draft202012Validator.check_schema(PLAN_SCHEMA)
    Draft202012Validator(PLAN_SCHEMA).validate(report)
    assert report["format"] == PLAN_FORMAT
    assert [row["request_id"] for row in report["selected_requests"]] == ["request-high", "request-mid"]
    assert report["spent_units"] == 5
    assert report["remaining_units"] == 0
    assert report["deferred_counts"] == {
        "subject_already_selected": 1,
        "over_budget": 1,
        "request_limit": 0,
    }


def test_evidence_request_plan_respects_request_limit_and_all_action_bounds() -> None:
    candidates = {
        "format": CANDIDATES_FORMAT,
        "candidates": [
            candidate("native", "subject-a", action="consumer_native_probe"),
            candidate("human", "subject-b", action="human_review"),
            candidate("callers", "subject-c", action="callers_callees"),
        ],
    }
    report = build_evidence_request_plan(
        candidates, candidates_sha256="c" * 64, budget_units=10, max_requests=1
    )

    assert len(report["selected_requests"]) == 1
    assert report["selected_requests"][0]["action_type"] == "callers_callees"
    assert report["deferred_counts"]["request_limit"] == 2


def test_all_reviewed_action_types_have_closed_bounded_shapes() -> None:
    candidates = {
        "format": CANDIDATES_FORMAT,
        "candidates": [
            candidate(f"request-{action}", f"subject-{action}", action=action)
            for action in sorted(ACTION_TYPES)
        ],
    }

    Draft202012Validator(CANDIDATES_SCHEMA).validate(candidates)
    report = build_evidence_request_plan(
        candidates,
        candidates_sha256="e" * 64,
        budget_units=len(ACTION_TYPES),
        max_requests=len(ACTION_TYPES),
    )
    Draft202012Validator(PLAN_SCHEMA).validate(report)
    assert {row["action_type"] for row in report["selected_requests"]} == ACTION_TYPES


def test_typed_native_probes_are_explicit_bounded_and_preserved() -> None:
    candidates = {
        "format": CANDIDATES_FORMAT,
        "candidates": [
            candidate(f"probe-{kind}", f"subject-{kind}", action="consumer_native_probe", probe_kind=kind)
            for kind in sorted(PROBE_KINDS)
        ],
    }

    Draft202012Validator(CANDIDATES_SCHEMA).validate(candidates)
    report = build_evidence_request_plan(
        candidates,
        candidates_sha256="f" * 64,
        budget_units=len(PROBE_KINDS),
        max_requests=len(PROBE_KINDS),
    )
    Draft202012Validator(PLAN_SCHEMA).validate(report)
    assert {row["probe_kind"] for row in report["selected_requests"]} == PROBE_KINDS
    assert all(row["bounds"] == {"max_steps": 100, "timeout_ms": 5000} for row in report["selected_requests"])


def test_legacy_generic_probe_remains_valid_and_typed_probes_are_scoped() -> None:
    generic = {"format": CANDIDATES_FORMAT, "candidates": [candidate("generic", "subject", action="consumer_native_probe")]}
    Draft202012Validator(CANDIDATES_SCHEMA).validate(generic)
    result = build_evidence_request_plan(generic, candidates_sha256="1" * 64, budget_units=1, max_requests=1)
    assert "probe_kind" not in result["selected_requests"][0]

    invalid = {"format": CANDIDATES_FORMAT, "candidates": [candidate("bad", "subject")]}
    invalid["candidates"][0]["probe_kind"] = "function_entry_exit"
    with pytest.raises(ValueError, match="invalid probe_kind"):
        build_evidence_request_plan(invalid, candidates_sha256="2" * 64, budget_units=1, max_requests=1)

    with_probe_code = {"format": CANDIDATES_FORMAT, "candidates": [candidate("code", "subject", action="consumer_native_probe")]}
    with_probe_code["candidates"][0]["probe_code"] = "instrumentation"
    with pytest.raises(ValueError, match="unexpected fields"):
        build_evidence_request_plan(with_probe_code, candidates_sha256="3" * 64, budget_units=1, max_requests=1)


@pytest.mark.parametrize("mutation, message", [
    (lambda row: row.update(approval_status="pending"), "must be explicitly approved"),
    (lambda row: row.update(action_type="run_arbitrary_probe"), "unsupported action_type"),
    (lambda row: row.update(bounds={"max_steps": 100}), "requires bounds"),
    (lambda row: row.update(bounds={"max_items": 10001}), "invalid max_items"),
    (lambda row: row.update(request_id="duplicate"), "duplicate request_id"),
])
def test_evidence_request_plan_fails_closed_on_unapproved_or_unbounded_actions(mutation, message: str) -> None:
    candidates = fixture()
    mutation(candidates["candidates"][0])
    if message == "duplicate request_id":
        candidates["candidates"][1]["request_id"] = "duplicate"
    with pytest.raises(ValueError, match=message):
        build_evidence_request_plan(candidates, candidates_sha256="d" * 64, budget_units=10, max_requests=10)


def test_evidence_request_cli_hashes_input_and_writes_plan(tmp_path: Path, capsys) -> None:
    source = fixture()
    source_path = tmp_path / "candidates.json"
    source_path.write_text(json.dumps(source), encoding="utf-8")
    output = tmp_path / "nested" / "plan.json"

    assert main([
        str(source_path), "--budget-units", "5", "--max-requests", "4", "--output", str(output)
    ]) == 0

    report = json.loads(output.read_text(encoding="utf-8"))
    Draft202012Validator(PLAN_SCHEMA).validate(report)
    assert report["source"]["candidates_sha256"] == hashlib.sha256(source_path.read_bytes()).hexdigest()
    assert "selected: 2" in capsys.readouterr().out
