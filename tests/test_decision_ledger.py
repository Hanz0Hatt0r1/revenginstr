from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.decision_ledger import audit_decision_ledger, main


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/decision-ledger/events.jsonl"
EVENT_SCHEMA = json.loads((ROOT / "schemas/analysis-decision-ledger-event-v1.schema.json").read_text(encoding="utf-8"))
AUDIT_SCHEMA = json.loads((ROOT / "schemas/analysis-decision-ledger-audit-v1.schema.json").read_text(encoding="utf-8"))


def _events():
    return [json.loads(line) for line in FIXTURE.read_text(encoding="utf-8").splitlines()]


def test_decision_ledger_fixtures_and_aggregate_match_schemas() -> None:
    events = _events()
    Draft202012Validator.check_schema(EVENT_SCHEMA)
    event_validator = Draft202012Validator(EVENT_SCHEMA)
    for event in events:
        event_validator.validate(event)

    report = audit_decision_ledger(sha256(FIXTURE.read_bytes()).hexdigest(), events)
    Draft202012Validator.check_schema(AUDIT_SCHEMA)
    Draft202012Validator(AUDIT_SCHEMA).validate(report)
    assert report["events"] == 7
    assert report["subjects"] == 6
    assert set(report["terminal_state_counts"].values()) == {1}
    assert report["terminal_state_counts"]["accepted_exact"] == 1
    assert report["reason_counts"]["evidence_conflict"] == 1


def test_decision_ledger_rejects_broken_chains_and_duplicate_event_ids() -> None:
    events = _events()
    events[1]["previous_state"] = "unsupported"
    with pytest.raises(ValueError, match="breaks the subject chain"):
        audit_decision_ledger("a" * 64, events)

    events = _events()
    events[1]["event_id"] = events[0]["event_id"]
    with pytest.raises(ValueError, match="duplicate event id"):
        audit_decision_ledger("a" * 64, events)

    events = _events()
    events[1]["subject_provenance"]["record_index"] += 1
    with pytest.raises(ValueError, match="breaks the subject chain"):
        audit_decision_ledger("a" * 64, events)


def test_decision_ledger_rejects_unsupported_reason_and_confidence_delta() -> None:
    events = _events()
    events[0]["reason_codes"] = ["game_specific_rule"]
    with pytest.raises(ValueError, match="invalid reason codes"):
        audit_decision_ledger("a" * 64, events)

    events = _events()
    events[2]["confidence_delta"] = 1.1
    with pytest.raises(ValueError, match="confidence_delta"):
        audit_decision_ledger("a" * 64, events)


def test_decision_ledger_cli_writes_identity_free_report(tmp_path: Path, capsys) -> None:
    output = tmp_path / "nested" / "audit.json"
    assert main([str(FIXTURE), "--output", str(output)]) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    Draft202012Validator(AUDIT_SCHEMA).validate(report)
    serialized = json.dumps(report)
    assert "function-synthetic" not in serialized
    assert "event-synthetic" not in serialized
    assert "events: 7" in capsys.readouterr().out
