"""Validate decision-ledger chains and emit identity-free aggregate counts."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

EVENT_FORMAT = "REVENGINSTR.AnalysisDecisionLedgerEvent/1"
AUDIT_FORMAT = "REVENGINSTR.AnalysisDecisionLedgerAudit/1"
STATES = (
    "accepted_exact", "accepted_high_confidence", "review_required",
    "escalated_conflict", "unsupported", "budget_exhausted",
)
REASONS = (
    "exact_evidence", "high_confidence", "out_of_distribution", "evidence_conflict",
    "unsupported_pattern", "missing_evidence", "budget_exhausted", "human_review",
)
EVIDENCE_CLASSES = {
    "exact_static", "runtime_native", "derived_structural", "model_prediction",
    "human_review", "interventional_probe",
}
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_EVENT_FIELDS = {
    "format", "analysis_id", "event_id", "subject_id", "subject_kind",
    "subject_provenance", "event_index",
    "previous_state", "state", "reason_codes", "responsible",
    "confidence_delta", "evidence_added",
}


def _read_events(path: Path) -> tuple[str, list[dict[str, Any]]]:
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"{path}: input must be UTF-8") from error
    events = []
    for line_no, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            raise ValueError(f"{path}:{line_no}: blank JSONL record")
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"{path}:{line_no}: invalid JSON") from error
        if not isinstance(event, dict):
            raise ValueError(f"{path}:{line_no}: expected object")
        events.append(event)
    return hashlib.sha256(raw).hexdigest(), events


def _nonempty(value: Any, where: str) -> bool:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{where}: expected non-empty string")
    return True


def _validate_event(event: dict[str, Any], row: int) -> None:
    where = f"ledger event {row}"
    if not isinstance(event, dict) or set(event) != _EVENT_FIELDS or event.get("format") != EVENT_FORMAT:
        raise ValueError(f"{where}: unexpected format or fields")
    for field in ("analysis_id", "event_id", "subject_id"):
        _nonempty(event[field], f"{where} {field}")
    if not isinstance(event["subject_kind"], str) or event["subject_kind"] not in {"function", "family", "claim", "decision"}:
        raise ValueError(f"{where}: unsupported subject kind")
    subject_provenance = event["subject_provenance"]
    if (
        not isinstance(subject_provenance, dict)
        or set(subject_provenance) != {"source_format", "artifact_sha256", "record_index"}
    ):
        raise ValueError(f"{where}: invalid subject provenance")
    _nonempty(subject_provenance["source_format"], f"{where} subject source_format")
    if not isinstance(subject_provenance["artifact_sha256"], str) or _SHA256.fullmatch(subject_provenance["artifact_sha256"]) is None:
        raise ValueError(f"{where}: invalid subject artifact SHA-256")
    subject_record_index = subject_provenance["record_index"]
    if not isinstance(subject_record_index, int) or isinstance(subject_record_index, bool) or subject_record_index < 1:
        raise ValueError(f"{where}: invalid subject artifact record index")
    index = event["event_index"]
    if not isinstance(index, int) or isinstance(index, bool) or index < 1:
        raise ValueError(f"{where}: event_index must be a positive integer")
    previous = event["previous_state"]
    if previous is not None and previous not in STATES:
        raise ValueError(f"{where}: unsupported previous state")
    if event["state"] not in STATES:
        raise ValueError(f"{where}: unsupported state")
    reasons = event["reason_codes"]
    if (
        not isinstance(reasons, list) or not reasons
        or any(not isinstance(reason, str) for reason in reasons)
        or len(reasons) != len(set(reasons)) or not set(reasons) <= set(REASONS)
    ):
        raise ValueError(f"{where}: invalid reason codes")
    responsible = event["responsible"]
    if not isinstance(responsible, dict) or set(responsible) != {"kind", "id"}:
        raise ValueError(f"{where}: invalid responsible actor")
    if not isinstance(responsible["kind"], str) or responsible["kind"] not in {"rule", "model", "human", "orchestrator"}:
        raise ValueError(f"{where}: unsupported responsible actor kind")
    _nonempty(responsible["id"], f"{where} responsible id")
    delta = event["confidence_delta"]
    if delta is not None and (
        not isinstance(delta, (int, float)) or isinstance(delta, bool)
        or not -1 <= delta <= 1
    ):
        raise ValueError(f"{where}: confidence_delta must be null or between -1 and 1")
    evidence = event["evidence_added"]
    if not isinstance(evidence, list):
        raise ValueError(f"{where}: evidence_added must be an array")
    seen_evidence: set[tuple[str, str, int, str]] = set()
    for evidence_index, item in enumerate(evidence, 1):
        if not isinstance(item, dict) or set(item) != {"source_format", "artifact_sha256", "record_index", "evidence_class"}:
            raise ValueError(f"{where} evidence {evidence_index}: unexpected fields")
        _nonempty(item["source_format"], f"{where} evidence {evidence_index} source_format")
        if not isinstance(item["artifact_sha256"], str) or _SHA256.fullmatch(item["artifact_sha256"]) is None:
            raise ValueError(f"{where} evidence {evidence_index}: invalid SHA-256")
        record_index = item["record_index"]
        if not isinstance(record_index, int) or isinstance(record_index, bool) or record_index < 1:
            raise ValueError(f"{where} evidence {evidence_index}: invalid record index")
        if not isinstance(item["evidence_class"], str) or item["evidence_class"] not in EVIDENCE_CLASSES:
            raise ValueError(f"{where} evidence {evidence_index}: unsupported evidence class")
        evidence_key = (item["source_format"], item["artifact_sha256"], record_index, item["evidence_class"])
        if evidence_key in seen_evidence:
            raise ValueError(f"{where}: duplicate evidence reference")
        seen_evidence.add(evidence_key)


def audit_decision_ledger(source_sha256: str, events: list[dict[str, Any]]) -> dict[str, Any]:
    """Check per-subject event chains; never apply a transition policy."""
    if not isinstance(source_sha256, str) or _SHA256.fullmatch(source_sha256) is None:
        raise ValueError("invalid ledger SHA-256")
    event_ids: set[str] = set()
    last: dict[tuple[str, str], tuple[int, str, tuple[Any, ...]]] = {}
    reason_counts = Counter({reason: 0 for reason in REASONS})
    transitions: Counter[tuple[str | None, str]] = Counter()
    analyses: set[str] = set()
    for row, event in enumerate(events, 1):
        _validate_event(event, row)
        if event["event_id"] in event_ids:
            raise ValueError(f"ledger event {row}: duplicate event id")
        event_ids.add(event["event_id"])
        analysis_id = event["analysis_id"]
        analyses.add(analysis_id)
        key = (analysis_id, event["subject_id"])
        prior = last.get(key)
        expected_index = 1 if prior is None else prior[0] + 1
        expected_state = None if prior is None else prior[1]
        provenance = event["subject_provenance"]
        subject_ref = (
            event["subject_kind"], provenance["source_format"],
            provenance["artifact_sha256"], provenance["record_index"],
        )
        if (
            event["event_index"] != expected_index
            or event["previous_state"] != expected_state
            or (prior is not None and prior[2] != subject_ref)
        ):
            raise ValueError(f"ledger event {row}: event index or previous state breaks the subject chain")
        last[key] = (event["event_index"], event["state"], subject_ref)
        reason_counts.update(event["reason_codes"])
        transitions[(expected_state, event["state"])] += 1

    terminal_counts = Counter({state: 0 for state in STATES})
    for _key, (_index, state, _subject_ref) in last.items():
        terminal_counts[state] += 1
    return {
        "format": AUDIT_FORMAT,
        "source_sha256": source_sha256,
        "events": len(events),
        "subjects": len(last),
        "analyses": len(analyses),
        "terminal_state_counts": dict(terminal_counts),
        "reason_counts": dict(reason_counts),
        "transition_counts": [
            {"previous_state": previous, "state": state, "count": count}
            for (previous, state), count in sorted(transitions.items(), key=lambda item: (item[0][0] or "", item[0][1]))
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    source_sha256, events = _read_events(args.events)
    report = audit_decision_ledger(source_sha256, events)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("events:", report["events"])
    print("subjects:", report["subjects"])
    print("output:", args.output)
    return 0
