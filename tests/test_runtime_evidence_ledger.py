from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.decision_ledger import audit_decision_ledger
from revenginstr.runtime_evidence_ledger import (
    RuntimeLedgerError,
    build_ledger_events,
)
from revenginstr.runtime_indirect_call_correlation import REPORT_FORMAT as INDIRECT_CALL_FORMAT
from revenginstr.runtime_value_flow import replay_value_flow

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "docs/evidence/runtime-value-flow-v1/nevergone-synthetic"
LEDGER_SCHEMA = json.loads((ROOT / "schemas/analysis-decision-ledger-event-v1.schema.json").read_text())
INDIRECT_CALL_SCHEMA = json.loads(
    (ROOT / "schemas/runtime-indirect-call-correlation-v1.schema.json").read_text()
)


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


def _indirect_call_report() -> dict:
    capture_id = "shift-dispatch-capture"
    matched = {
        "capture_id": capture_id,
        "sequence": 0,
        "caller_runtime_address": "0x70010000",
        "callsite_runtime_address": "0x70010040",
        "target_runtime_address": "0x70020000",
        "caller_address": "0x10000",
        "callsite_address": "0x10040",
        "target_address": "0x20000",
        "caller_match_state": "matched",
        "callsite_match_state": "matched",
        "target_match_state": "matched",
        "caller_node_ids": ["function-caller"],
        "callsite_node_ids": ["operation-callind"],
        "target_node_ids": ["function-target"],
        "match_state": "matched",
    }
    unmatched_target = {
        **matched,
        "sequence": 1,
        "target_runtime_address": "0x70030000",
        "target_address": "0x30000",
        "target_match_state": "unmatched",
        "target_node_ids": [],
        "match_state": "unmatched_target",
    }
    return {
        "format": INDIRECT_CALL_FORMAT,
        "capture_id": capture_id,
        "program_id": "shift.exe:sha256:test",
        "program_sha256": "a" * 64,
        "static_identity_sha256": "b" * 64,
        "semantic_graph_sha256": "c" * 64,
        "capture_manifest_sha256": "d" * 64,
        "observations_sha256": "e" * 64,
        "address_mapping": {
            "method": "runtime_address_minus_module_delta",
            "runtime_module_base": "0x70000000",
            "static_image_base": "0x10000",
            "module_delta": "0x6fff0000",
        },
        "sampling": {"status": "sampled", "gaps": []},
        "summary": {
            "event_count": 2,
            "match_state_counts": {"matched": 1, "unmatched_target": 1},
        },
        "events": [matched, unmatched_target],
    }


def test_indirect_call_observations_become_review_only_ledger_events() -> None:
    report = _indirect_call_report()
    Draft202012Validator(INDIRECT_CALL_SCHEMA).validate(report)
    report_raw = (json.dumps(report, sort_keys=True) + "\n").encode()
    events = build_ledger_events(report, report_raw)
    assert len(events) == 2
    assert events[0]["subject_id"] != events[1]["subject_id"]
    assert [event["reason_codes"] for event in events] == [["human_review"], ["missing_evidence"]]
    for event in events:
        Draft202012Validator(LEDGER_SCHEMA).validate(event)
        assert event["state"] == "review_required"
        assert event["confidence_delta"] is None
        assert event["evidence_added"][0]["evidence_class"] == "runtime_native"
    ledger_raw = b"".join((json.dumps(event, sort_keys=True) + "\n").encode() for event in events)
    audit = audit_decision_ledger(hashlib.sha256(ledger_raw).hexdigest(), events)
    assert audit["events"] == 2
    assert audit["terminal_state_counts"]["accepted_exact"] == 0


def test_indirect_call_ledger_rejects_inconsistent_match_counts() -> None:
    report = _indirect_call_report()
    report["summary"]["match_state_counts"] = {"matched": 2}
    report_raw = (json.dumps(report, sort_keys=True) + "\n").encode()
    with pytest.raises(RuntimeLedgerError, match="match_state_counts"):
        build_ledger_events(report, report_raw)
