"""Convert bounded runtime analysis reports into decision-ledger events."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from revenginstr.runtime_indirect_call_correlation import (
    MAX_EVENTS as MAX_INDIRECT_EVENTS,
    REPORT_FORMAT as INDIRECT_CALL_FORMAT,
)
from revenginstr.runtime_static_correlation import (
    MAX_EVENTS as MAX_STATIC_EVENTS,
    REPORT_FORMAT as STATIC_CORRELATION_FORMAT,
)

INPUT_FORMAT = "REVENGINSTR.RuntimeValueFlowReplay/1"
EVENT_FORMAT = "REVENGINSTR.AnalysisDecisionLedgerEvent/1"
MAX_CANDIDATES = 10_000
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RESULT_FIELDS = {
    "candidate_id", "relation_kind", "source_sequence", "sink_sequence",
    "expected_source_node_id", "expected_sink_node_id", "status", "reason",
    "compared_token_slots", "intervening_coverage",
}
_INDIRECT_REPORT_FIELDS = {
    "format", "capture_id", "program_id", "program_sha256", "static_identity_sha256",
    "semantic_graph_sha256", "capture_manifest_sha256", "observations_sha256",
    "address_mapping", "sampling", "summary", "events",
}
_STATIC_REPORT_FIELDS = {
    "format", "capture_id", "program_id", "program_sha256", "static_identity_sha256",
    "semantic_graph_sha256", "capture_manifest_sha256", "observations_sha256",
    "address_mapping", "sampling", "summary", "events",
}
_INDIRECT_EVENT_FIELDS = {
    "capture_id", "sequence", "caller_runtime_address", "callsite_runtime_address",
    "target_runtime_address", "caller_address", "callsite_address", "target_address",
    "caller_match_state", "callsite_match_state", "target_match_state",
    "caller_node_ids", "callsite_node_ids", "target_node_ids", "match_state",
}
_INDIRECT_MATCH_STATES = {
    "matched", "unmatched_callsite", "ambiguous_callsite", "unmatched_caller",
    "ambiguous_caller", "unmatched_target", "ambiguous_target",
    "mapping_underflow", "mapping_overflow",
}
_MATCH_COMPONENT_STATES = {"matched", "unmatched", "ambiguous", "mapping_underflow", "mapping_overflow"}


class RuntimeLedgerError(ValueError):
    """Runtime report cannot be replayed into ledger records."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _read_json(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    if len(raw) > 64 * 1024 * 1024:
        raise RuntimeLedgerError(f"{path}: input exceeds 64 MiB")
    try:
        report = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise RuntimeLedgerError(f"{path}: invalid JSON: {error}") from error
    if not isinstance(report, dict):
        raise RuntimeLedgerError(f"{path}: expected a JSON object")
    return report, raw


def build_ledger_events(report: dict[str, Any], report_raw: bytes) -> list[dict[str, Any]]:
    if report.get("format") == INDIRECT_CALL_FORMAT:
        return _build_indirect_call_ledger_events(report, report_raw)
    if report.get("format") == STATIC_CORRELATION_FORMAT:
        return _build_static_correlation_ledger_events(report, report_raw)
    report_fields = {
        "format", "capture_id", "program_id", "program_sha256", "semantic_graph_sha256",
        "correlation_report_sha256", "observations_sha256", "sampling", "claim_scope",
        "token_provenance", "summary", "candidates",
    }
    if set(report) != report_fields or report.get("format") != INPUT_FORMAT or report.get("claim_scope") != "selected_observation_pairs_only":
        raise RuntimeLedgerError("expected a pair-scoped RuntimeValueFlowReplay/1 report")
    if not isinstance(report.get("capture_id"), str) or not report["capture_id"].strip():
        raise RuntimeLedgerError("runtime report has invalid capture_id")
    for field in ("program_sha256", "semantic_graph_sha256", "correlation_report_sha256", "observations_sha256"):
        if not isinstance(report[field], str) or _SHA256.fullmatch(report[field]) is None:
            raise RuntimeLedgerError(f"runtime report has invalid {field}")
    report_sha = hashlib.sha256(report_raw).hexdigest()
    candidates = report.get("candidates")
    if not isinstance(candidates, list) or not 1 <= len(candidates) <= MAX_CANDIDATES:
        raise RuntimeLedgerError("runtime report must contain 1 to 10000 candidate results")

    analysis_id = f"runtime-value-flow-{report_sha[:24]}"
    events = []
    seen_candidates: set[str] = set()
    for index, result in enumerate(candidates, 1):
        if not isinstance(result, dict) or set(result) != _RESULT_FIELDS:
            raise RuntimeLedgerError(f"runtime result {index}: expected an object")
        candidate_id, status = result.get("candidate_id"), result.get("status")
        if not isinstance(candidate_id, str) or not candidate_id.strip() or candidate_id in seen_candidates:
            raise RuntimeLedgerError(f"runtime result {index}: candidate ids must be non-empty and unique")
        seen_candidates.add(candidate_id)
        if status == "witnessed":
            state, reason = "review_required", "human_review"
        elif status == "observed_mismatch":
            state, reason = "escalated_conflict", "evidence_conflict"
        elif status == "inconclusive":
            state, reason = "review_required", "missing_evidence"
        else:
            raise RuntimeLedgerError(f"runtime result {index}: unsupported status")
        event_hash = hashlib.sha256(f"{report_sha}\0{candidate_id}".encode("utf-8")).hexdigest()
        evidence = {
            "source_format": INPUT_FORMAT,
            "artifact_sha256": report_sha,
            "record_index": index,
            "evidence_class": "runtime_native",
        }
        events.append({
            "format": EVENT_FORMAT,
            "analysis_id": analysis_id,
            "event_id": f"runtime-value-flow-{event_hash}",
            "subject_id": candidate_id,
            "subject_kind": "claim",
            "subject_provenance": {
                "source_format": INPUT_FORMAT,
                "artifact_sha256": report_sha,
                "record_index": index,
            },
            "event_index": 1,
            "previous_state": None,
            "state": state,
            "reason_codes": [reason],
            "responsible": {"kind": "orchestrator", "id": "revenginstr-runtime-value-flow"},
            "confidence_delta": None,
            "evidence_added": [evidence],
        })
    return events


def _indirect_match_state(event: dict[str, Any]) -> str:
    caller = event["caller_match_state"]
    callsite = event["callsite_match_state"]
    target = event["target_match_state"]
    if caller in {"mapping_underflow", "mapping_overflow"}:
        return caller
    if callsite in {"mapping_underflow", "mapping_overflow"}:
        return callsite
    if caller != "matched":
        return f"{caller}_caller"
    if callsite != "matched":
        return f"{callsite}_callsite"
    if target in {"mapping_underflow", "mapping_overflow"}:
        return target
    if target != "matched":
        return f"{target}_target"
    return "matched"


def _validate_indirect_call_report(report: dict[str, Any]) -> list[dict[str, Any]]:
    if set(report) != _INDIRECT_REPORT_FIELDS or report.get("format") != INDIRECT_CALL_FORMAT:
        raise RuntimeLedgerError("expected a RuntimeIndirectCallCorrelation/1 report")
    for field in ("capture_id", "program_id"):
        if not isinstance(report[field], str) or not report[field].strip():
            raise RuntimeLedgerError(f"runtime report has invalid {field}")
    for field in (
        "program_sha256", "static_identity_sha256", "semantic_graph_sha256",
        "capture_manifest_sha256", "observations_sha256",
    ):
        if not isinstance(report[field], str) or _SHA256.fullmatch(report[field]) is None:
            raise RuntimeLedgerError(f"runtime report has invalid {field}")

    events = report.get("events")
    if not isinstance(events, list) or not 1 <= len(events) <= MAX_INDIRECT_EVENTS:
        raise RuntimeLedgerError(f"runtime report must contain 1 to {MAX_INDIRECT_EVENTS} call events")
    summary = report.get("summary")
    if not isinstance(summary, dict) or set(summary) != {"event_count", "match_state_counts"}:
        raise RuntimeLedgerError("runtime report has invalid summary")
    if (
        not isinstance(summary["event_count"], int)
        or isinstance(summary["event_count"], bool)
        or summary["event_count"] != len(events)
    ):
        raise RuntimeLedgerError("runtime report event_count does not match events")
    summary_counts = summary["match_state_counts"]
    if not isinstance(summary_counts, dict):
        raise RuntimeLedgerError("runtime report has invalid match_state_counts")
    if any(
        state not in _INDIRECT_MATCH_STATES
        or not isinstance(count, int) or isinstance(count, bool) or count < 1
        for state, count in summary_counts.items()
    ):
        raise RuntimeLedgerError("runtime report has invalid match_state_counts")

    observed_counts: Counter[str] = Counter()
    previous_sequence = -1
    for index, event in enumerate(events, 1):
        if not isinstance(event, dict) or set(event) != _INDIRECT_EVENT_FIELDS:
            raise RuntimeLedgerError(f"runtime event {index}: unexpected fields")
        if event["capture_id"] != report["capture_id"]:
            raise RuntimeLedgerError(f"runtime event {index}: capture_id mismatch")
        sequence = event["sequence"]
        if (
            not isinstance(sequence, int) or isinstance(sequence, bool)
            or not 0 <= sequence <= 1_000_000_000 or sequence <= previous_sequence
        ):
            raise RuntimeLedgerError(f"runtime event {index}: sequence must be unique and increasing")
        previous_sequence = sequence
        for field in ("caller_runtime_address", "callsite_runtime_address", "target_runtime_address"):
            if not isinstance(event[field], str) or not event[field]:
                raise RuntimeLedgerError(f"runtime event {index}: missing {field}")
        for component in ("caller", "callsite", "target"):
            address = event[f"{component}_address"]
            state = event[f"{component}_match_state"]
            node_ids = event[f"{component}_node_ids"]
            if not isinstance(state, str) or state not in _MATCH_COMPONENT_STATES:
                raise RuntimeLedgerError(f"runtime event {index}: invalid {component} match state")
            if not isinstance(node_ids, list) or any(not isinstance(node_id, str) or not node_id for node_id in node_ids):
                raise RuntimeLedgerError(f"runtime event {index}: invalid {component} node ids")
            if len(node_ids) != len(set(node_ids)):
                raise RuntimeLedgerError(f"runtime event {index}: duplicate {component} node ids")
            expected_count = {"matched": 1, "unmatched": 0, "ambiguous": "many"}.get(state, 0)
            if expected_count == "many":
                if len(node_ids) < 2:
                    raise RuntimeLedgerError(f"runtime event {index}: ambiguous {component} needs multiple node ids")
            elif len(node_ids) != expected_count:
                raise RuntimeLedgerError(f"runtime event {index}: node ids disagree with {component} match state")
            if state in {"mapping_underflow", "mapping_overflow"}:
                if address is not None:
                    raise RuntimeLedgerError(f"runtime event {index}: unmapped {component} address must be null")
            elif not isinstance(address, str) or not address:
                raise RuntimeLedgerError(f"runtime event {index}: invalid normalized {component} address")

        match_state = event["match_state"]
        if (
            not isinstance(match_state, str)
            or match_state not in _INDIRECT_MATCH_STATES
            or match_state != _indirect_match_state(event)
        ):
            raise RuntimeLedgerError(f"runtime event {index}: match_state disagrees with component matches")
        observed_counts[match_state] += 1
    if summary_counts != dict(observed_counts):
        raise RuntimeLedgerError("runtime report match_state_counts do not match events")
    return events


def _build_indirect_call_ledger_events(
    report: dict[str, Any], report_raw: bytes,
) -> list[dict[str, Any]]:
    events = _validate_indirect_call_report(report)
    return _build_observation_ledger_events(
        report, report_raw, events, source_format=INDIRECT_CALL_FORMAT, label="indirect-call",
    )


def _validate_static_correlation_report(report: dict[str, Any]) -> list[dict[str, Any]]:
    if set(report) != _STATIC_REPORT_FIELDS or report.get("format") != STATIC_CORRELATION_FORMAT:
        raise RuntimeLedgerError("expected a RuntimeStaticCorrelation/1 report")
    for field in ("capture_id", "program_id"):
        if not isinstance(report[field], str) or not report[field].strip():
            raise RuntimeLedgerError(f"runtime report has invalid {field}")
    for field in (
        "program_sha256", "static_identity_sha256", "semantic_graph_sha256",
        "capture_manifest_sha256", "observations_sha256",
    ):
        if not isinstance(report[field], str) or _SHA256.fullmatch(report[field]) is None:
            raise RuntimeLedgerError(f"runtime report has invalid {field}")
    events = report.get("events")
    if not isinstance(events, list) or not 1 <= len(events) <= MAX_STATIC_EVENTS:
        raise RuntimeLedgerError(f"runtime report must contain 1 to {MAX_STATIC_EVENTS} events")
    summary = report.get("summary")
    summary_fields = {
        "event_count", "matched_count", "ambiguous_count", "unmatched_count",
        "mapping_underflow_count", "mapping_overflow_count",
    }
    if not isinstance(summary, dict) or set(summary) != summary_fields:
        raise RuntimeLedgerError("runtime report has invalid summary")
    if any(
        not isinstance(count, int) or isinstance(count, bool) or count < 0
        for count in summary.values()
    ) or summary["event_count"] != len(events):
        raise RuntimeLedgerError("runtime report summary does not match events")

    counts: Counter[str] = Counter()
    previous_sequence = -1
    for index, event in enumerate(events, 1):
        if not isinstance(event, dict) or set(event) != {
            "capture_id", "sequence", "event_kind", "runtime_address", "normalized_address",
            "match_state", "matched_node_ids", "function_entries",
        }:
            raise RuntimeLedgerError(f"runtime event {index}: unexpected fields")
        if event["capture_id"] != report["capture_id"]:
            raise RuntimeLedgerError(f"runtime event {index}: capture_id mismatch")
        sequence = event["sequence"]
        if (
            not isinstance(sequence, int) or isinstance(sequence, bool)
            or not 0 <= sequence <= 1_000_000_000 or sequence <= previous_sequence
        ):
            raise RuntimeLedgerError(f"runtime event {index}: sequence must be unique and increasing")
        previous_sequence = sequence
        if event["event_kind"] not in {"function_entry", "function_exit", "call_target", "instruction"}:
            raise RuntimeLedgerError(f"runtime event {index}: unsupported event_kind")
        if not isinstance(event["runtime_address"], str) or not event["runtime_address"]:
            raise RuntimeLedgerError(f"runtime event {index}: invalid runtime_address")
        match_state = event["match_state"]
        if not isinstance(match_state, str) or match_state not in _MATCH_COMPONENT_STATES:
            raise RuntimeLedgerError(f"runtime event {index}: invalid match_state")
        node_ids = event["matched_node_ids"]
        entries = event["function_entries"]
        if (
            not isinstance(node_ids, list)
            or any(not isinstance(node_id, str) or not node_id for node_id in node_ids)
            or len(node_ids) != len(set(node_ids))
            or not isinstance(entries, list)
            or any(not isinstance(entry, str) or not entry for entry in entries)
            or len(entries) != len(set(entries))
        ):
            raise RuntimeLedgerError(f"runtime event {index}: invalid node identities")
        expected_count = {"matched": 1, "unmatched": 0, "ambiguous": "many"}.get(match_state, 0)
        if expected_count == "many":
            if len(node_ids) < 2:
                raise RuntimeLedgerError(f"runtime event {index}: ambiguous match needs multiple nodes")
        elif len(node_ids) != expected_count:
            raise RuntimeLedgerError(f"runtime event {index}: node ids disagree with match_state")
        normalized = event["normalized_address"]
        if match_state in {"mapping_underflow", "mapping_overflow"}:
            if normalized is not None:
                raise RuntimeLedgerError(f"runtime event {index}: unmapped address must be null")
        elif not isinstance(normalized, str) or not normalized:
            raise RuntimeLedgerError(f"runtime event {index}: invalid normalized_address")
        counts[match_state] += 1

    expected_summary = {
        "event_count": len(events),
        "matched_count": counts["matched"],
        "ambiguous_count": counts["ambiguous"],
        "unmatched_count": counts["unmatched"],
        "mapping_underflow_count": counts["mapping_underflow"],
        "mapping_overflow_count": counts["mapping_overflow"],
    }
    if summary != expected_summary:
        raise RuntimeLedgerError("runtime report summary counts do not match events")
    return events


def _build_static_correlation_ledger_events(
    report: dict[str, Any], report_raw: bytes,
) -> list[dict[str, Any]]:
    events = _validate_static_correlation_report(report)
    return _build_observation_ledger_events(
        report, report_raw, events, source_format=STATIC_CORRELATION_FORMAT, label="static-correlation",
    )


def _build_observation_ledger_events(
    report: dict[str, Any], report_raw: bytes, observations: list[dict[str, Any]], *,
    source_format: str, label: str,
) -> list[dict[str, Any]]:
    report_sha = hashlib.sha256(report_raw).hexdigest()
    analysis_id = f"runtime-{label}-{report_sha[:24]}"
    ledger_events = []
    for index, result in enumerate(observations, 1):
        subject_seed = "\0".join((report["program_id"], report["capture_id"], str(result["sequence"])))
        subject_hash = hashlib.sha256(subject_seed.encode("utf-8")).hexdigest()
        reason = "human_review" if result["match_state"] == "matched" else "missing_evidence"
        event_hash = hashlib.sha256(f"{report_sha}\0{index}".encode("utf-8")).hexdigest()
        evidence = {
            "source_format": source_format,
            "artifact_sha256": report_sha,
            "record_index": index,
            "evidence_class": "runtime_native",
        }
        ledger_events.append({
            "format": EVENT_FORMAT,
            "analysis_id": analysis_id,
            "event_id": f"runtime-{label}-{event_hash}",
            "subject_id": f"runtime-{label}-observation-{subject_hash}",
            "subject_kind": "claim",
            "subject_provenance": {
                "source_format": source_format,
                "artifact_sha256": report_sha,
                "record_index": index,
            },
            "event_index": 1,
            "previous_state": None,
            "state": "review_required",
            "reason_codes": [reason],
            "responsible": {"kind": "orchestrator", "id": f"revenginstr-runtime-{label}"},
            "confidence_delta": None,
            "evidence_added": [evidence],
        })
    return ledger_events


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("runtime_report", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.resolve() == args.runtime_report.resolve():
        raise RuntimeLedgerError("output path must not replace the runtime report")
    report, report_raw = _read_json(args.runtime_report)
    events = build_ledger_events(report, report_raw)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in events), encoding="utf-8")
    print("ledger events:", len(events))
    print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
