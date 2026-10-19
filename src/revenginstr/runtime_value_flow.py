"""Replay selected runtime value-flow pairs against pinned static locations."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from bisect import bisect_right
from pathlib import Path
from typing import Any

MANIFEST_FORMAT = "REVENGINSTR.RuntimeValueFlowManifest/1"
OBSERVATION_FORMAT = "REVENGINSTR.RuntimeValueObservation/1"
CORRELATION_FORMAT = "REVENGINSTR.RuntimeStaticCorrelation/1"
REPORT_FORMAT = "REVENGINSTR.RuntimeValueFlowReplay/1"
MAX_ROWS = 100_000
MAX_CANDIDATES = 10_000
MAX_SEQUENCE = 1_000_000_000
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ADDRESS = re.compile(r"^(?:0x)?([0-9a-fA-F]{1,16})$")
_TOKEN = re.compile(r"^hmac-sha256:[0-9a-f]{64}$")
_EVENT_TOKENS = {
    "receiver": {"subject"},
    "field_write": {"subject", "field", "value"},
    "field_read": {"subject", "field", "value"},
    "state_before": {"subject", "value"},
    "state_after": {"subject", "value"},
    "factory_return": {"subject"},
    "factory_use": {"subject"},
    "allocation": {"subject"},
    "release": {"subject"},
}
_RELATIONS = {
    "receiver_identity": ("receiver", "receiver"),
    "field_write_read": ("field_write", "field_read"),
    "state_transition": ("state_before", "state_after"),
    "factory_return_use": ("factory_return", "factory_use"),
    "allocation_release": ("allocation", "release"),
}


class RuntimeValueFlowError(ValueError):
    """Pinned value-flow inputs cannot be replayed safely."""


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
        raise RuntimeValueFlowError(f"{path}: input exceeds 64 MiB")
    try:
        if jsonl:
            value = [
                json.loads(line, object_pairs_hook=_unique_object)
                for line in raw.decode("utf-8").splitlines() if line.strip()
            ]
        else:
            value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise RuntimeValueFlowError(f"{path}: invalid JSON: {error}") from error
    return value, raw


def _sha256(value: Any, where: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise RuntimeValueFlowError(f"{where}: expected lowercase SHA-256")
    return value


def _sequence(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_SEQUENCE:
        raise RuntimeValueFlowError(f"{where}: invalid sequence")
    return value


def _validate_inputs(
    manifest: Any, correlation: Any, correlation_raw: bytes,
    observations: Any, observations_raw: bytes,
) -> tuple[list[dict[str, Any]], dict[int, dict[str, Any]], dict[int, dict[str, Any]]]:
    if not isinstance(manifest, dict) or set(manifest) != {
        "format", "capture_id", "correlation_report_sha256", "observations_sha256", "candidates",
    } or manifest.get("format") != MANIFEST_FORMAT:
        raise RuntimeValueFlowError("unsupported or malformed value-flow manifest")
    if not isinstance(manifest["capture_id"], str) or not manifest["capture_id"].strip():
        raise RuntimeValueFlowError("manifest: invalid capture_id")
    if hashlib.sha256(correlation_raw).hexdigest() != _sha256(
        manifest["correlation_report_sha256"], "manifest correlation_report_sha256",
    ):
        raise RuntimeValueFlowError("correlation report hash mismatch")
    if hashlib.sha256(observations_raw).hexdigest() != _sha256(
        manifest["observations_sha256"], "manifest observations_sha256",
    ):
        raise RuntimeValueFlowError("value observations hash mismatch")
    if not isinstance(correlation, dict) or set(correlation) != {
        "format", "capture_id", "program_id", "program_sha256", "static_identity_sha256",
        "semantic_graph_sha256", "capture_manifest_sha256", "observations_sha256",
        "address_mapping", "sampling", "summary", "events",
    } or correlation.get("format") != CORRELATION_FORMAT:
        raise RuntimeValueFlowError("expected a RuntimeStaticCorrelation/1 report")
    if correlation["capture_id"] != manifest["capture_id"]:
        raise RuntimeValueFlowError("manifest capture_id does not match correlation report")
    if not isinstance(correlation.get("program_id"), str) or not correlation["program_id"].strip():
        raise RuntimeValueFlowError("correlation report has invalid program_id")
    for key in (
        "program_sha256", "static_identity_sha256", "semantic_graph_sha256",
        "capture_manifest_sha256", "observations_sha256",
    ):
        _sha256(correlation[key], f"correlation {key}")
    sampling = correlation["sampling"]
    if (
        not isinstance(sampling, dict) or set(sampling) != {"status", "gaps"}
        or not isinstance(sampling["status"], str)
        or sampling["status"] not in {"complete", "sampled", "unknown"}
        or not isinstance(sampling["gaps"], list) or len(sampling["gaps"]) > 10_000
    ):
        raise RuntimeValueFlowError("correlation report has invalid sampling metadata")
    gaps = []
    previous_last = -1
    for gap in sampling["gaps"]:
        if not isinstance(gap, dict) or set(gap) != {"first_sequence", "last_sequence", "reason"}:
            raise RuntimeValueFlowError("correlation report has malformed sampling gap")
        first = _sequence(gap["first_sequence"], "sampling gap first_sequence")
        last = _sequence(gap["last_sequence"], "sampling gap last_sequence")
        if (
            last < first or first <= previous_last
            or not isinstance(gap["reason"], str) or not gap["reason"].strip()
        ):
            raise RuntimeValueFlowError("correlation report has invalid sampling gap")
        gaps.append((first, last))
        previous_last = last
    if sampling["status"] == "complete" and gaps or sampling["status"] == "sampled" and not gaps:
        raise RuntimeValueFlowError("correlation sampling status conflicts with declared gaps")

    events = correlation["events"]
    if not isinstance(events, list) or not 1 <= len(events) <= MAX_ROWS:
        raise RuntimeValueFlowError("correlation report has invalid event count")
    by_sequence: dict[int, dict[str, Any]] = {}
    for event in events:
        if not isinstance(event, dict):
            raise RuntimeValueFlowError("correlation event must be an object")
        sequence = _sequence(event.get("sequence"), "correlation event sequence")
        if sequence in by_sequence or event.get("capture_id") != manifest["capture_id"]:
            raise RuntimeValueFlowError("duplicate sequence or capture mismatch in correlation report")
        address = event.get("runtime_address")
        if not isinstance(address, str) or _ADDRESS.fullmatch(address) is None:
            raise RuntimeValueFlowError("correlation event has invalid runtime_address")
        nodes = event.get("matched_node_ids")
        if not isinstance(nodes, list) or not all(isinstance(node, str) and node for node in nodes):
            raise RuntimeValueFlowError("correlation event has invalid matched_node_ids")
        if event.get("match_state") not in {"matched", "ambiguous", "unmatched", "mapping_underflow", "mapping_overflow"}:
            raise RuntimeValueFlowError("correlation event has invalid match_state")
        by_sequence[sequence] = event
    ordered_sequences = sorted(by_sequence)
    gap_starts = [first for first, _ in gaps]
    for sequence in ordered_sequences:
        gap_index = bisect_right(gap_starts, sequence) - 1
        if gap_index >= 0 and sequence <= gaps[gap_index][1]:
            raise RuntimeValueFlowError("sampling gap overlaps a correlated event")
    for previous, current in zip(ordered_sequences, ordered_sequences[1:]):
        cursor = previous + 1
        gap_index = max(0, bisect_right(gap_starts, cursor) - 1)
        while cursor < current:
            if gap_index >= len(gaps) or gaps[gap_index][0] > cursor:
                raise RuntimeValueFlowError("correlation sequence gap is undeclared")
            cursor = gaps[gap_index][1] + 1
            gap_index += 1
        if sampling["status"] == "complete" and current != previous + 1:
            raise RuntimeValueFlowError("complete correlation contains a sequence gap")

    if not isinstance(observations, list) or not 1 <= len(observations) <= MAX_ROWS:
        raise RuntimeValueFlowError("value observations must be a bounded non-empty JSONL list")
    value_by_sequence: dict[int, dict[str, Any]] = {}
    for row in observations:
        if not isinstance(row, dict) or set(row) != {
            "format", "capture_id", "correlation_sequence", "event_kind", "runtime_address", "tokens",
        }:
            raise RuntimeValueFlowError("value observation has unexpected fields")
        sequence = _sequence(row["correlation_sequence"], "value observation correlation_sequence")
        if sequence in value_by_sequence or row["format"] != OBSERVATION_FORMAT:
            raise RuntimeValueFlowError("duplicate sequence or unsupported value observation format")
        if row["capture_id"] != manifest["capture_id"]:
            raise RuntimeValueFlowError("value observation capture_id mismatch")
        kind = row["event_kind"]
        tokens = row["tokens"]
        if (
            not isinstance(kind, str) or kind not in _EVENT_TOKENS or not isinstance(tokens, dict)
            or set(tokens) != _EVENT_TOKENS[kind]
            or any(not isinstance(token, str) or _TOKEN.fullmatch(token) is None for token in tokens.values())
        ):
            raise RuntimeValueFlowError(f"value observation {sequence}: invalid event kind or opaque tokens")
        address = row["runtime_address"]
        if not isinstance(address, str) or _ADDRESS.fullmatch(address) is None:
            raise RuntimeValueFlowError(f"value observation {sequence}: invalid runtime_address")
        value_by_sequence[sequence] = row

    candidates = manifest["candidates"]
    if not isinstance(candidates, list) or not 1 <= len(candidates) <= MAX_CANDIDATES:
        raise RuntimeValueFlowError(f"manifest candidates must contain 1 to {MAX_CANDIDATES} rows")
    seen: set[str] = set()
    for candidate in candidates:
        fields = {
            "candidate_id", "relation_kind", "source_sequence", "sink_sequence",
            "expected_source_node_id", "expected_sink_node_id",
        }
        if not isinstance(candidate, dict) or set(candidate) != fields:
            raise RuntimeValueFlowError("candidate has unexpected fields")
        candidate_id = candidate["candidate_id"]
        if not isinstance(candidate_id, str) or not candidate_id.strip() or candidate_id in seen:
            raise RuntimeValueFlowError("candidate_id must be non-empty and unique")
        seen.add(candidate_id)
        if not isinstance(candidate["relation_kind"], str) or candidate["relation_kind"] not in _RELATIONS:
            raise RuntimeValueFlowError(f"candidate {candidate_id}: unsupported relation_kind")
        source = _sequence(candidate["source_sequence"], f"candidate {candidate_id} source_sequence")
        sink = _sequence(candidate["sink_sequence"], f"candidate {candidate_id} sink_sequence")
        if source >= sink:
            raise RuntimeValueFlowError(f"candidate {candidate_id}: source must precede sink")
        for key in ("expected_source_node_id", "expected_sink_node_id"):
            if not isinstance(candidate[key], str) or not candidate[key].strip():
                raise RuntimeValueFlowError(f"candidate {candidate_id}: invalid {key}")
    return candidates, by_sequence, value_by_sequence


def replay_value_flow(
    manifest: Any, correlation: Any, correlation_raw: bytes,
    observations: Any, observations_raw: bytes,
) -> dict[str, Any]:
    """Replay explicit observation pairs; never make a whole-program claim."""
    candidates, address_events, value_events = _validate_inputs(
        manifest, correlation, correlation_raw, observations, observations_raw,
    )
    gaps = correlation["sampling"]["gaps"]
    status = correlation["sampling"]["status"]
    results = []
    for candidate in candidates:
        source_seq, sink_seq = candidate["source_sequence"], candidate["sink_sequence"]
        source_addr, sink_addr = address_events.get(source_seq), address_events.get(sink_seq)
        source, sink = value_events.get(source_seq), value_events.get(sink_seq)
        result = {
            "candidate_id": candidate["candidate_id"],
            "relation_kind": candidate["relation_kind"],
            "source_sequence": source_seq,
            "sink_sequence": sink_seq,
            "expected_source_node_id": candidate["expected_source_node_id"],
            "expected_sink_node_id": candidate["expected_sink_node_id"],
            "status": "inconclusive",
            "reason": None,
            "compared_token_slots": [],
        }
        if any(gap["first_sequence"] <= sink_seq and gap["last_sequence"] >= source_seq for gap in gaps):
            result["reason"] = "declared_sampling_gap_intersects_pair"
        elif source_addr is None or sink_addr is None or source is None or sink is None:
            result["reason"] = "selected_observation_missing"
        elif any(
            row["match_state"] != "matched" or row["matched_node_ids"] != [candidate[node_key]]
            for row, node_key in (
                (source_addr, "expected_source_node_id"), (sink_addr, "expected_sink_node_id"),
            )
        ):
            result["reason"] = "static_location_not_uniquely_matched_to_expected_node"
        elif any(
            int(value["runtime_address"].removeprefix("0x"), 16)
            != int(address["runtime_address"].removeprefix("0x"), 16)
            for value, address in ((source, source_addr), (sink, sink_addr))
        ):
            result["reason"] = "value_observation_address_does_not_match_correlation"
        else:
            expected_kinds = _RELATIONS[candidate["relation_kind"]]
            if (source["event_kind"], sink["event_kind"]) != expected_kinds:
                result["reason"] = "event_kind_pair_does_not_match_relation"
            else:
                source_tokens, sink_tokens = source["tokens"], sink["tokens"]
                compared = sorted(set(source_tokens) & set(sink_tokens))
                result["compared_token_slots"] = compared
                equal = [slot for slot in compared if source_tokens[slot] == sink_tokens[slot]]
                different = [slot for slot in compared if source_tokens[slot] != sink_tokens[slot]]
                relation = candidate["relation_kind"]
                if relation == "state_transition":
                    witnessed = "subject" in equal and "value" in different
                else:
                    witnessed = len(equal) == len(compared)
                if witnessed:
                    result.update(status="witnessed", reason="selected_pair_satisfies_relation")
                else:
                    result.update(status="observed_mismatch", reason="selected_pair_tokens_conflict")
                    result["different_token_slots"] = different
        result["intervening_coverage"] = (
            "complete" if status == "complete" else "not_established"
        )
        results.append(result)

    counts = {state: sum(row["status"] == state for row in results) for state in (
        "witnessed", "observed_mismatch", "inconclusive",
    )}
    return {
        "format": REPORT_FORMAT,
        "capture_id": manifest["capture_id"],
        "program_id": correlation["program_id"],
        "program_sha256": correlation["program_sha256"],
        "semantic_graph_sha256": correlation["semantic_graph_sha256"],
        "correlation_report_sha256": hashlib.sha256(correlation_raw).hexdigest(),
        "observations_sha256": hashlib.sha256(observations_raw).hexdigest(),
        "sampling": {"status": status, "gaps": gaps},
        "claim_scope": "selected_observation_pairs_only",
        "token_provenance": "Opaque HMAC-shaped tokens are caller supplied; the replay cannot verify their secret or authenticity.",
        "summary": {"candidate_count": len(results), **counts},
        "candidates": results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("correlation_report", type=Path)
    parser.add_argument("value_observations", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    inputs = {path.resolve() for path in (args.manifest, args.correlation_report, args.value_observations)}
    if args.output.resolve() in inputs:
        raise RuntimeValueFlowError("output path must not replace an input")
    manifest, _ = _read_json(args.manifest)
    correlation, correlation_raw = _read_json(args.correlation_report)
    observations, observations_raw = _read_json(args.value_observations, jsonl=True)
    report = replay_value_flow(manifest, correlation, correlation_raw, observations, observations_raw)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("candidate pairs:", report["summary"]["candidate_count"])
    print("witnessed:", report["summary"]["witnessed"])
    print("observed mismatch:", report["summary"]["observed_mismatch"])
    print("inconclusive:", report["summary"]["inconclusive"])
    print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
