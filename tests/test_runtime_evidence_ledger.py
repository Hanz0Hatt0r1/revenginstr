from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.decision_ledger import audit_decision_ledger
from revenginstr.runtime_evidence_ledger import RuntimeLedgerError, build_ledger_events
from revenginstr.runtime_value_flow import replay_value_flow

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "docs/evidence/runtime-value-flow-v1/nevergone-synthetic"
LEDGER_SCHEMA = json.loads((ROOT / "schemas/analysis-decision-ledger-event-v1.schema.json").read_text())


def _report() -> dict:
    manifest = json.loads((FIXTURE / "manifest.json").read_text())
    correlation_raw = (FIXTURE / "correlation-report.json").read_bytes()
    correlation = json.loads(correlation_raw)
    observations_raw = (FIXTURE / "value-observations.jsonl").read_bytes()
    observations = [json.loads(line) for line in observations_raw.splitlines() if line.strip()]
    return replay_value_flow(manifest, correlation, correlation_raw, observations, observations_raw)


def test_runtime_value_results_become_auditable_non_accepting_events() -> None:
    report = _report()
    report_raw = (json.dumps(report, sort_keys=True) + "\n").encode()
    events = build_ledger_events(report, report_raw)
    for event in events:
        Draft202012Validator(LEDGER_SCHEMA).validate(event)
        assert event["state"] == "review_required"
        assert event["confidence_delta"] is None
        assert event["evidence_added"][0]["artifact_sha256"] == hashlib.sha256(report_raw).hexdigest()
    ledger_raw = b"".join((json.dumps(event, sort_keys=True) + "\n").encode() for event in events)
    audit = audit_decision_ledger(hashlib.sha256(ledger_raw).hexdigest(), events)
    assert audit["events"] == 1
    assert audit["terminal_state_counts"]["accepted_exact"] == 0


@pytest.mark.parametrize(
    ("status", "state", "reason"),
    [
        ("witnessed", "review_required", "human_review"),
        ("observed_mismatch", "escalated_conflict", "evidence_conflict"),
        ("inconclusive", "review_required", "missing_evidence"),
    ],
)
def test_each_runtime_outcome_has_a_cautious_ledger_transition(status: str, state: str, reason: str) -> None:
    report = deepcopy(_report())
    report["candidates"][0]["status"] = status
    report_raw = (json.dumps(report, sort_keys=True) + "\n").encode()
    event = build_ledger_events(report, report_raw)[0]
    assert event["state"] == state
    assert event["reason_codes"] == [reason]


def test_duplicate_candidate_ids_are_rejected() -> None:
    report = _report()
    report["candidates"].append(deepcopy(report["candidates"][0]))
    report_raw = (json.dumps(report, sort_keys=True) + "\n").encode()
    with pytest.raises(RuntimeLedgerError, match="unique"):
        build_ledger_events(report, report_raw)
