"""Replay consumer-reported bounded transform observations against exact runtime joins."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

MANIFEST_FORMAT = "REVENGINSTR.RuntimeTransformReplayManifest/1"
OBSERVATION_FORMAT = "REVENGINSTR.RuntimeTransformObservation/1"
CORRELATION_FORMAT = "REVENGINSTR.RuntimeStaticCorrelation/1"
REPORT_FORMAT = "REVENGINSTR.RuntimeTransformReplay/1"
MAX_ROWS = 100_000
MAX_SEQUENCE = 1_000_000_000
MAX_U32 = (1 << 32) - 1
MAX_SAMPLES = 128
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ADDRESS = re.compile(r"^(?:0x)?([0-9a-fA-F]{1,16})$")


class RuntimeTransformReplayError(ValueError):
    """Pinned transform evidence cannot be replayed safely."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _read(path: Path, *, jsonl: bool = False) -> tuple[Any, bytes]:
    raw = path.read_bytes()
    if len(raw) > 64 * 1024 * 1024:
        raise RuntimeTransformReplayError(f"{path}: input exceeds 64 MiB")
    try:
        text = raw.decode("utf-8")
        value = (
            [json.loads(line, object_pairs_hook=_unique_object) for line in text.splitlines() if line.strip()]
            if jsonl else json.loads(text, object_pairs_hook=_unique_object)
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise RuntimeTransformReplayError(f"{path}: invalid JSON: {error}") from error
    return value, raw


def _hash(value: Any, where: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise RuntimeTransformReplayError(f"{where}: expected lowercase SHA-256")
    return value


def _sequence(value: Any, where: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= MAX_SEQUENCE:
        raise RuntimeTransformReplayError(f"{where}: invalid sequence")
    return value


def _address(value: Any, where: str) -> int:
    if not isinstance(value, str):
        raise RuntimeTransformReplayError(f"{where}: expected a hexadecimal address")
    match = _ADDRESS.fullmatch(value)
    if match is None:
        raise RuntimeTransformReplayError(f"{where}: invalid hexadecimal address")
    return int(match.group(1), 16)


def _nonempty(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RuntimeTransformReplayError(f"{where}: expected a non-empty string")
    return value


def replay_runtime_transforms(
    manifest: Any,
    manifest_sha256: str,
    correlation: Any,
    correlation_raw: bytes,
    observations: Any,
    observations_raw: bytes,
) -> dict[str, Any]:
    """Join bounded consumer transform results to exact static function nodes.

    The consumer computes formula results from live buffers. This replay validates
    the consumer hashes, sample bounds, event identity, and exact static join; it
    does not authenticate the consumer or recompute a formula without sample bytes.
    """
    manifest_fields = {
        "format", "capture_id", "candidate_id", "behavior_id", "expected_function_node_id",
        "correlation_report_sha256", "observations_sha256", "source_capture_sha256", "probe_script_sha256",
    }
    if not isinstance(manifest, dict) or set(manifest) != manifest_fields or manifest.get("format") != MANIFEST_FORMAT:
        raise RuntimeTransformReplayError("unsupported or malformed runtime-transform manifest")
    capture_id = _nonempty(manifest["capture_id"], "manifest capture_id")
    candidate_id = _nonempty(manifest["candidate_id"], "manifest candidate_id")
    behavior_id = _nonempty(manifest["behavior_id"], "manifest behavior_id")
    expected_node = _nonempty(manifest["expected_function_node_id"], "manifest expected_function_node_id")
    for key in ("correlation_report_sha256", "observations_sha256", "source_capture_sha256", "probe_script_sha256"):
        _hash(manifest[key], f"manifest {key}")
    if hashlib.sha256(correlation_raw).hexdigest() != manifest["correlation_report_sha256"]:
        raise RuntimeTransformReplayError("correlation report hash mismatch")
    if hashlib.sha256(observations_raw).hexdigest() != manifest["observations_sha256"]:
        raise RuntimeTransformReplayError("transform observations hash mismatch")
    _hash(manifest_sha256, "manifest SHA-256")

    corr_fields = {
        "format", "capture_id", "program_id", "program_sha256", "static_identity_sha256",
        "semantic_graph_sha256", "capture_manifest_sha256", "observations_sha256", "address_mapping",
        "sampling", "summary", "events",
    }
    if not isinstance(correlation, dict) or set(correlation) != corr_fields or correlation.get("format") != CORRELATION_FORMAT:
        raise RuntimeTransformReplayError("expected a RuntimeStaticCorrelation/1 report")
    if correlation["capture_id"] != capture_id:
        raise RuntimeTransformReplayError("manifest capture_id does not match static correlation")
    for key in ("program_sha256", "static_identity_sha256", "semantic_graph_sha256", "capture_manifest_sha256", "observations_sha256"):
        _hash(correlation[key], f"correlation {key}")
    sampling = correlation["sampling"]
    if (
        not isinstance(sampling, dict) or set(sampling) != {"status", "gaps"}
        or not isinstance(sampling.get("status"), str)
        or sampling["status"] not in {"complete", "sampled", "unknown"}
        or not isinstance(sampling.get("gaps"), list) or len(sampling["gaps"]) > 10_000
    ):
        raise RuntimeTransformReplayError("correlation report has invalid sampling metadata")
    previous_gap_end = -1
    for gap in sampling["gaps"]:
        if not isinstance(gap, dict) or set(gap) != {"first_sequence", "last_sequence", "reason"}:
            raise RuntimeTransformReplayError("correlation report has malformed sampling gap")
        first = _sequence(gap["first_sequence"], "sampling gap first_sequence")
        last = _sequence(gap["last_sequence"], "sampling gap last_sequence")
        if (
            last < first or first <= previous_gap_end
            or not isinstance(gap["reason"], str) or not gap["reason"].strip()
        ):
            raise RuntimeTransformReplayError("correlation report has invalid sampling gap")
        previous_gap_end = last
    if sampling["status"] == "complete" and sampling["gaps"] or sampling["status"] == "sampled" and not sampling["gaps"]:
        raise RuntimeTransformReplayError("correlation sampling status conflicts with declared gaps")
    if not isinstance(correlation["events"], list) or len(correlation["events"]) > MAX_ROWS:
        raise RuntimeTransformReplayError("correlation report has invalid events")
    by_sequence: dict[int, dict[str, Any]] = {}
    for event in correlation["events"]:
        if not isinstance(event, dict) or event.get("capture_id") != capture_id:
            raise RuntimeTransformReplayError("correlation event has invalid capture_id")
        sequence = _sequence(event.get("sequence"), "correlation event sequence")
        if sequence in by_sequence:
            raise RuntimeTransformReplayError("duplicate correlation event sequence")
        _address(event.get("runtime_address"), "correlation runtime_address")
        if not isinstance(event.get("event_kind"), str) or event["event_kind"] not in {"function_entry", "function_exit", "call_target", "instruction"}:
            raise RuntimeTransformReplayError("correlation event has invalid event_kind")
        if not isinstance(event.get("match_state"), str) or event["match_state"] not in {"matched", "ambiguous", "unmatched", "mapping_underflow", "mapping_overflow"}:
            raise RuntimeTransformReplayError("correlation event has invalid match_state")
        nodes = event.get("matched_node_ids")
        if not isinstance(nodes, list) or not all(isinstance(node, str) and node for node in nodes):
            raise RuntimeTransformReplayError("correlation event has invalid matched nodes")
        by_sequence[sequence] = event

    if not isinstance(observations, list) or not 1 <= len(observations) <= MAX_ROWS:
        raise RuntimeTransformReplayError("transform observations must be a bounded non-empty JSONL list")
    expected_fields = {
        "format", "capture_id", "correlation_sequence", "runtime_address", "event_kind", "behavior_id",
        "source_ordinal", "input_length", "key", "sample_mode", "sample_count", "formula_result",
        "probe_script_sha256",
    }
    seen_sequences: set[int] = set()
    seen_ordinals: set[int] = set()
    output = []
    counts = {key: 0 for key in ("full_match", "sampled_match", "observed_mismatch", "inconclusive")}
    exact_count = 0
    for index, row in enumerate(observations, 1):
        where = f"transform observation {index}"
        if not isinstance(row, dict) or set(row) != expected_fields or row.get("format") != OBSERVATION_FORMAT:
            raise RuntimeTransformReplayError(f"{where}: unsupported or malformed observation")
        if row["capture_id"] != capture_id or row["behavior_id"] != behavior_id:
            raise RuntimeTransformReplayError(f"{where}: capture or behavior mismatch")
        if row["event_kind"] != "function_entry":
            raise RuntimeTransformReplayError(f"{where}: only function-entry observations are supported")
        if row["probe_script_sha256"] != manifest["probe_script_sha256"]:
            raise RuntimeTransformReplayError(f"{where}: probe script hash mismatch")
        sequence = _sequence(row["correlation_sequence"], f"{where} correlation_sequence")
        ordinal = _sequence(row["source_ordinal"], f"{where} source_ordinal")
        if sequence in seen_sequences or ordinal == 0 or ordinal in seen_ordinals:
            raise RuntimeTransformReplayError(f"{where}: duplicate or invalid source sequence")
        seen_sequences.add(sequence)
        seen_ordinals.add(ordinal)
        address = _address(row["runtime_address"], f"{where} runtime_address")
        length, key, sample_count = row["input_length"], row["key"], row["sample_count"]
        for value, maximum, field in ((length, MAX_U32, "input_length"), (key, MAX_U32, "key"), (sample_count, MAX_SAMPLES, "sample_count")):
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
                raise RuntimeTransformReplayError(f"{where}: invalid {field}")
        mode, result = row["sample_mode"], row["formula_result"]
        if (
            not isinstance(mode, str) or mode not in {"none", "full", "bounded"}
            or not isinstance(result, str) or result not in {"match", "mismatch", "unavailable"}
        ):
            raise RuntimeTransformReplayError(f"{where}: invalid sample mode or formula result")
        if mode == "none" and (sample_count != 0 or result != "unavailable"):
            raise RuntimeTransformReplayError(f"{where}: empty sample must be unavailable")
        if mode == "full" and (not 0 < length <= MAX_SAMPLES or sample_count > length):
            raise RuntimeTransformReplayError(f"{where}: invalid full-sample bounds")
        if mode == "bounded" and (length <= MAX_SAMPLES or sample_count > MAX_SAMPLES):
            raise RuntimeTransformReplayError(f"{where}: invalid bounded-sample bounds")
        if result in {"match", "mismatch"} and sample_count == 0:
            raise RuntimeTransformReplayError(f"{where}: formula result requires checked samples")
        if result == "match" and mode == "full" and sample_count != length:
            raise RuntimeTransformReplayError(f"{where}: full match has incomplete coverage")

        event = by_sequence.get(sequence)
        static_nodes = event.get("matched_node_ids", []) if event else []
        exact = bool(
            event
            and event.get("event_kind") == "function_entry"
            and event.get("runtime_address") is not None
            and _address(event["runtime_address"], "correlation runtime_address") == address
            and event.get("match_state") == "matched"
            and static_nodes == [expected_node]
        )
        if exact:
            exact_count += 1
            outcome = (
                "observed_mismatch" if result == "mismatch"
                else "inconclusive" if result == "unavailable"
                else "full_match" if mode == "full"
                else "sampled_match"
            )
        else:
            outcome = "inconclusive"
        counts[outcome] += 1
        output.append({
            "correlation_sequence": sequence,
            "runtime_address": f"0x{address:x}",
            "source_ordinal": ordinal,
            "static_match_state": event.get("match_state", "missing") if event else "missing",
            "matched_node_ids": static_nodes,
            "input_length": length,
            "key": key,
            "sample_mode": mode,
            "sample_count": sample_count,
            "formula_result": result,
            "outcome": outcome,
            "evidence_class": "runtime_consumer_reported",
        })

    return {
        "format": REPORT_FORMAT,
        "capture_id": capture_id,
        "candidate_id": candidate_id,
        "behavior_id": behavior_id,
        "expected_function_node_id": expected_node,
        "manifest_sha256": manifest_sha256,
        "correlation_report_sha256": manifest["correlation_report_sha256"],
        "observations_sha256": manifest["observations_sha256"],
        "source_capture_sha256": manifest["source_capture_sha256"],
        "probe_script_sha256": manifest["probe_script_sha256"],
        "sampling": sampling,
        "summary": {
            "observation_count": len(output),
            "exact_static_match_count": exact_count,
            "full_match_count": counts["full_match"],
            "sampled_match_count": counts["sampled_match"],
            "observed_mismatch_count": counts["observed_mismatch"],
            "inconclusive_count": counts["inconclusive"],
        },
        "observations": output,
        "evidence_limitations": [
            "Formula results are consumer-reported; sample bytes are not included or recomputed by the analyzer.",
            "The source capture and probe hashes identify inputs but do not authenticate their origin.",
            "A bounded sample match does not prove whole-buffer behavior or capture completeness.",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("static_correlation", type=Path)
    parser.add_argument("observations", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    inputs = [args.manifest, args.static_correlation, args.observations]
    if args.output.resolve() in {path.resolve() for path in inputs}:
        raise RuntimeTransformReplayError("output path must not replace an input")
    manifest, manifest_raw = _read(args.manifest)
    correlation, correlation_raw = _read(args.static_correlation)
    observations, observations_raw = _read(args.observations, jsonl=True)
    report = replay_runtime_transforms(
        manifest, hashlib.sha256(manifest_raw).hexdigest(),
        correlation, correlation_raw, observations, observations_raw,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("runtime transform observations:", report["summary"]["observation_count"])
    print("exact static matches:", report["summary"]["exact_static_match_count"])
    print("sampled matches:", report["summary"]["sampled_match_count"])
    print("full matches:", report["summary"]["full_match_count"])
    print("observed mismatches:", report["summary"]["observed_mismatch_count"])
    print("inconclusive:", report["summary"]["inconclusive_count"])
    print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
