"""Convert pair-scoped runtime value-flow results into decision-ledger events."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

INPUT_FORMAT = "REVENGINSTR.RuntimeValueFlowReplay/1"
EVENT_FORMAT = "REVENGINSTR.AnalysisDecisionLedgerEvent/1"
MAX_CANDIDATES = 10_000
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_RESULT_FIELDS = {
    "candidate_id", "relation_kind", "source_sequence", "sink_sequence",
    "expected_source_node_id", "expected_sink_node_id", "status", "reason",
    "compared_token_slots", "intervening_coverage",
}


class RuntimeLedgerError(ValueError):
    """Runtime value-flow report cannot be replayed into ledger records."""


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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("runtime_value_flow_report", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.resolve() == args.runtime_value_flow_report.resolve():
        raise RuntimeLedgerError("output path must not replace the runtime report")
    report, report_raw = _read_json(args.runtime_value_flow_report)
    events = build_ledger_events(report, report_raw)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("".join(json.dumps(event, sort_keys=True) + "\n" for event in events), encoding="utf-8")
    print("ledger events:", len(events))
    print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
