"""Correlate bounded runtime address observations with a pinned static graph."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from bisect import bisect_right
from collections import Counter
from pathlib import Path
from typing import Any

from revenginstr.semantic_program_graph import FORMAT_V3, _read_jsonl, validate_graph_references

STATIC_IDENTITY_FORMAT = "REVENGINSTR.RuntimeStaticIdentity/1"
CAPTURE_FORMAT = "REVENGINSTR.RuntimeCaptureManifest/1"
OBSERVATION_FORMAT = "REVENGINSTR.RuntimeAddressObservation/1"
REPORT_FORMAT = "REVENGINSTR.RuntimeStaticCorrelation/1"
EVENT_KINDS = {"function_entry", "function_exit", "call_target", "instruction"}
MAX_EVENTS = 100_000
MAX_SEQUENCE = 1_000_000_000
MAX_ADDRESS = (1 << 64) - 1
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ADDRESS = re.compile(r"^(?:0x)?([0-9a-fA-F]{1,16})$")
_SIGNED_HEX = re.compile(r"^(-?)0x([0-9a-fA-F]{1,16})$")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _read_json(path: Path) -> tuple[dict[str, Any], str]:
    raw = path.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"{path}: invalid JSON: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value, hashlib.sha256(raw).hexdigest()


def _digest(value: Any, where: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{where}: expected lowercase SHA-256")
    return value


def _address(value: Any, where: str) -> int:
    if not isinstance(value, str):
        raise ValueError(f"{where}: expected a hexadecimal address string")
    match = _ADDRESS.fullmatch(value)
    if match is None:
        raise ValueError(f"{where}: unsupported hexadecimal address")
    return int(match.group(1), 16)


def _load_bias(value: Any) -> int:
    if not isinstance(value, str):
        raise ValueError("load_bias: expected a signed hexadecimal string")
    match = _SIGNED_HEX.fullmatch(value)
    if match is None:
        raise ValueError("load_bias: expected 0x-prefixed hexadecimal")
    magnitude = int(match.group(2), 16)
    return -magnitude if match.group(1) else magnitude


def _manifest_fields(value: dict[str, Any], expected: set[str], where: str) -> None:
    if set(value) != expected:
        raise ValueError(f"{where}: unexpected fields")


def _read_static_identity(value: dict[str, Any]) -> dict[str, Any]:
    fields = {"format", "program_id", "program_sha256", "semantic_graph_sha256"}
    _manifest_fields(value, fields, "static identity")
    if value["format"] != STATIC_IDENTITY_FORMAT:
        raise ValueError("unsupported static identity format")
    if not isinstance(value["program_id"], str) or not value["program_id"]:
        raise ValueError("static identity: invalid program_id")
    _digest(value["program_sha256"], "static identity program_sha256")
    _digest(value["semantic_graph_sha256"], "static identity semantic_graph_sha256")
    return value


def _read_capture(value: dict[str, Any]) -> dict[str, Any]:
    fields = {
        "format", "capture_id", "program_id", "program_sha256",
        "static_identity_sha256", "load_bias", "sampling_status", "sampling_gaps",
    }
    _manifest_fields(value, fields, "capture manifest")
    if value["format"] != CAPTURE_FORMAT:
        raise ValueError("unsupported runtime capture manifest format")
    capture = dict(value)
    for key in ("capture_id", "program_id"):
        if not isinstance(capture[key], str) or not capture[key]:
            raise ValueError(f"capture manifest: invalid {key}")
    _digest(capture["program_sha256"], "capture program_sha256")
    _digest(capture["static_identity_sha256"], "capture static_identity_sha256")
    capture["_load_bias"] = _load_bias(capture["load_bias"])
    status = capture["sampling_status"]
    gaps = capture["sampling_gaps"]
    if not isinstance(status, str) or status not in {"complete", "sampled", "unknown"}:
        raise ValueError("capture manifest: unsupported sampling_status")
    if not isinstance(gaps, list) or len(gaps) > 10_000:
        raise ValueError("capture manifest: sampling_gaps must be a bounded array")
    previous_last = -1
    for index, gap in enumerate(gaps, 1):
        if not isinstance(gap, dict) or set(gap) != {"first_sequence", "last_sequence", "reason"}:
            raise ValueError(f"sampling gap {index}: unexpected fields")
        first, last, reason = gap["first_sequence"], gap["last_sequence"], gap["reason"]
        if (
            isinstance(first, bool) or not isinstance(first, int) or not 0 <= first <= MAX_SEQUENCE
            or isinstance(last, bool) or not isinstance(last, int) or not first <= last <= MAX_SEQUENCE
            or not isinstance(reason, str) or not reason.strip()
            or first <= previous_last
        ):
            raise ValueError(f"sampling gap {index}: invalid or overlapping sequence range")
        previous_last = last
    if status == "complete" and gaps:
        raise ValueError("complete capture cannot declare sampling gaps")
    if status == "sampled" and not gaps:
        raise ValueError("sampled capture must declare sampling gaps")
    return capture


def _validate_observations(
    rows: list[dict[str, Any]], capture_id: str, gaps: list[dict[str, Any]], sampling_status: str,
) -> list[dict[str, Any]]:
    if not rows:
        raise ValueError("runtime observations are empty")
    if len(rows) > MAX_EVENTS:
        raise ValueError(f"runtime observations exceed {MAX_EVENTS} events")
    result = []
    sequences: set[int] = set()
    for index, row in enumerate(rows, 1):
        where = f"observation {index}"
        if set(row) != {"format", "capture_id", "sequence", "event_kind", "runtime_address"}:
            raise ValueError(f"{where}: unexpected fields")
        if row["format"] != OBSERVATION_FORMAT or row["capture_id"] != capture_id:
            raise ValueError(f"{where}: wrong format or capture_id")
        sequence = row["sequence"]
        if (
            isinstance(sequence, bool) or not isinstance(sequence, int)
            or not 0 <= sequence <= MAX_SEQUENCE or sequence in sequences
        ):
            raise ValueError(f"{where}: invalid or duplicate sequence")
        sequences.add(sequence)
        if not isinstance(row["event_kind"], str) or row["event_kind"] not in EVENT_KINDS:
            raise ValueError(f"{where}: unsupported event_kind")
        _address(row["runtime_address"], f"{where} runtime_address")
        result.append(row)
    result.sort(key=lambda row: row["sequence"])

    gap_starts = [gap["first_sequence"] for gap in gaps]
    for previous, current in zip(result, result[1:]):
        cursor = previous["sequence"] + 1
        last = current["sequence"] - 1
        gap_index = max(0, bisect_right(gap_starts, cursor) - 1)
        while cursor <= last and gap_index < len(gaps):
            gap = gaps[gap_index]
            if gap["last_sequence"] < cursor:
                gap_index += 1
                continue
            if gap["first_sequence"] > cursor:
                break
            cursor = gap["last_sequence"] + 1
            gap_index += 1
        if cursor <= last:
            raise ValueError("runtime sequence gap is not declared in the capture manifest")
    for sequence in sequences:
        gap_index = max(0, bisect_right(gap_starts, sequence) - 1)
        if gap_index < len(gaps) and gaps[gap_index]["first_sequence"] <= sequence <= gaps[gap_index]["last_sequence"]:
            raise ValueError("sampling gap overlaps an observed sequence")
    if sampling_status == "complete" and any(
        current["sequence"] != previous["sequence"] + 1 for previous, current in zip(result, result[1:])
    ):
        raise ValueError("complete capture contains a sequence gap")
    return result


def correlate_runtime_addresses(
    graph: dict[str, Any],
    *,
    graph_sha256: str,
    static_identity: dict[str, Any],
    static_identity_sha256: str,
    capture: dict[str, Any],
    capture_sha256: str,
    observations: list[dict[str, Any]],
    observations_sha256: str,
) -> dict[str, Any]:
    """Join only exact normalized function and operation addresses."""
    _digest(graph_sha256, "semantic graph SHA-256")
    _digest(static_identity_sha256, "static identity SHA-256")
    _digest(capture_sha256, "capture manifest SHA-256")
    _digest(observations_sha256, "runtime observations SHA-256")
    identity = _read_static_identity(static_identity)
    capture = _read_capture(capture)
    if graph.get("format") != FORMAT_V3:
        raise ValueError("runtime correlation requires SemanticProgramGraph/3")
    validate_graph_references(graph)
    if identity["semantic_graph_sha256"] != graph_sha256:
        raise ValueError("static identity does not pin this Semantic Program Graph")
    if graph.get("program_id") != identity["program_id"]:
        raise ValueError("static graph program_id does not match static identity")
    if capture["static_identity_sha256"] != static_identity_sha256:
        raise ValueError("runtime capture does not pin this static identity")
    for key in ("program_id", "program_sha256"):
        if capture[key] != identity[key]:
            raise ValueError(f"runtime/static {key} mismatch")

    load_bias = capture["_load_bias"]
    functions: dict[int, list[dict[str, Any]]] = {}
    operations: dict[int, list[dict[str, Any]]] = {}
    for node in graph["nodes"]:
        if node.get("kind") == "function":
            functions.setdefault(_address(node.get("entry"), f"function node {node.get('id')} entry"), []).append(node)
        elif node.get("kind") == "operation":
            operations.setdefault(
                _address(node.get("operation_address"), f"operation node {node.get('id')} address"), [],
            ).append(node)

    events = []
    counts: Counter[str] = Counter()
    ordered_observations = _validate_observations(
        observations, capture["capture_id"], capture["sampling_gaps"], capture["sampling_status"],
    )
    for row in ordered_observations:
        runtime_address = _address(row["runtime_address"], "runtime_address")
        normalized = runtime_address - load_bias
        if normalized < 0:
            state = "mapping_underflow"
            matched_nodes: list[dict[str, Any]] = []
            normalized_string = None
        elif normalized > MAX_ADDRESS:
            state = "mapping_overflow"
            matched_nodes = []
            normalized_string = None
        else:
            normalized_string = f"0x{normalized:x}"
            candidates = (
                functions.get(normalized, [])
                if row["event_kind"] in {"function_entry", "function_exit", "call_target"}
                else operations.get(normalized, [])
            )
            matched_nodes = sorted(candidates, key=lambda node: node["id"])
            state = "unmatched" if not matched_nodes else "matched" if len(matched_nodes) == 1 else "ambiguous"
        function_entries = {
            node.get("entry", node.get("function_entry"))
            for node in matched_nodes
            if isinstance(node.get("entry", node.get("function_entry")), str)
        }
        counts[state] += 1
        events.append({
            "capture_id": capture["capture_id"],
            "sequence": row["sequence"],
            "event_kind": row["event_kind"],
            "runtime_address": row["runtime_address"],
            "normalized_address": normalized_string,
            "match_state": state,
            "matched_node_ids": [node["id"] for node in matched_nodes],
            "function_entries": sorted(function_entries),
        })

    return {
        "format": REPORT_FORMAT,
        "capture_id": capture["capture_id"],
        "program_id": identity["program_id"],
        "program_sha256": identity["program_sha256"],
        "static_identity_sha256": static_identity_sha256,
        "semantic_graph_sha256": graph_sha256,
        "capture_manifest_sha256": capture_sha256,
        "observations_sha256": observations_sha256,
        "address_mapping": {"method": "runtime_address_minus_load_bias", "load_bias": capture["load_bias"]},
        "sampling": {"status": capture["sampling_status"], "gaps": capture["sampling_gaps"]},
        "summary": {
            "event_count": len(events),
            "matched_count": counts["matched"],
            "ambiguous_count": counts["ambiguous"],
            "unmatched_count": counts["unmatched"],
            "mapping_underflow_count": counts["mapping_underflow"],
            "mapping_overflow_count": counts["mapping_overflow"],
        },
        "events": events,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("semantic_program_graph", type=Path)
    parser.add_argument("static_identity", type=Path)
    parser.add_argument("capture_manifest", type=Path)
    parser.add_argument("observations", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    inputs = [args.semantic_program_graph, args.static_identity, args.capture_manifest, args.observations]
    if args.output.resolve() in {path.resolve() for path in inputs}:
        raise ValueError("output path must not replace an input")
    graphs, graph_sha256 = _read_jsonl(args.semantic_program_graph)
    if len(graphs) != 1:
        raise ValueError("runtime correlation requires exactly one semantic graph")
    identity, identity_sha256 = _read_json(args.static_identity)
    capture, capture_sha256 = _read_json(args.capture_manifest)
    observations, observations_sha256 = _read_jsonl(args.observations)
    report = correlate_runtime_addresses(
        graphs[0], graph_sha256=graph_sha256,
        static_identity=identity, static_identity_sha256=identity_sha256,
        capture=capture, capture_sha256=capture_sha256,
        observations=observations, observations_sha256=observations_sha256,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("runtime events:", report["summary"]["event_count"])
    print("matched:", report["summary"]["matched_count"])
    print("ambiguous:", report["summary"]["ambiguous_count"])
    print("unmatched:", report["summary"]["unmatched_count"])
    print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
