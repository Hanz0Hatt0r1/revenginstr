"""Correlate bounded runtime indirect-call events with pinned static graph sites."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from revenginstr.runtime_static_correlation import (
    MAX_ADDRESS,
    MAX_EVENTS,
    MAX_SEQUENCE,
    _address,
    _digest,
    _read_capture,
    _read_json as _read_runtime_json,
    _read_static_identity,
    _signed_hex,
    _validate_observations as _validate_address_observations,
)
from revenginstr.semantic_program_graph import (
    FORMAT_V3,
    _read_jsonl,
    validate_graph_references,
)

OBSERVATION_FORMAT = "REVENGINSTR.RuntimeIndirectCallObservation/1"
REPORT_FORMAT = "REVENGINSTR.RuntimeIndirectCallCorrelation/1"


def _read_observations(
    path: Path,
) -> tuple[list[dict[str, Any]], str]:
    if path.stat().st_size > 64 * 1024 * 1024:
        raise ValueError(f"{path}: input exceeds 64 MiB")
    rows, digest = _read_jsonl(path)
    if not 1 <= len(rows) <= MAX_EVENTS:
        raise ValueError(f"runtime indirect-call observations must contain 1 to {MAX_EVENTS} rows")
    return rows, digest


def _validate_indirect_observations(
    rows: list[dict[str, Any]], capture: dict[str, Any],
) -> list[dict[str, Any]]:
    if not 1 <= len(rows) <= MAX_EVENTS:
        raise ValueError(f"runtime indirect-call observations must contain 1 to {MAX_EVENTS} rows")
    capture_id = capture["capture_id"]
    validated = []
    for index, row in enumerate(rows, 1):
        where = f"observation {index}"
        if set(row) != {
            "format", "capture_id", "sequence", "caller_runtime_address",
            "callsite_runtime_address", "target_runtime_address",
        }:
            raise ValueError(f"{where}: unexpected fields")
        if row["format"] != OBSERVATION_FORMAT or row["capture_id"] != capture_id:
            raise ValueError(f"{where}: wrong format or capture_id")
        sequence = row["sequence"]
        if (
            isinstance(sequence, bool) or not isinstance(sequence, int)
            or not 0 <= sequence <= MAX_SEQUENCE
        ):
            raise ValueError(f"{where}: invalid sequence")
        for key in ("caller_runtime_address", "callsite_runtime_address", "target_runtime_address"):
            _address(row[key], f"{where} {key}")
        validated.append(row)
    # Reuse the existing capture's gap and sequence checks without widening its v1 schema.
    sequence_rows = [
        {
            "format": "REVENGINSTR.RuntimeAddressObservation/1",
            "capture_id": row["capture_id"],
            "sequence": row["sequence"],
            "event_kind": "call_target",
            "runtime_address": row["target_runtime_address"],
        }
        for row in validated
    ]
    ordered = _validate_address_observations(
        sequence_rows, capture_id, capture["sampling_gaps"], capture["sampling_status"],
    )
    by_sequence = {row["sequence"]: row for row in validated}
    return [by_sequence[row["sequence"]] for row in ordered]


def _normalize(address: str, delta: int) -> tuple[str | None, str]:
    normalized = _address(address, "runtime address") - delta
    if normalized < 0:
        return None, "mapping_underflow"
    if normalized > MAX_ADDRESS:
        return None, "mapping_overflow"
    return f"0x{normalized:x}", "mapped"


def _match(nodes: list[dict[str, Any]]) -> tuple[str, list[str]]:
    ids = sorted(node["id"] for node in nodes)
    return ("unmatched" if not ids else "matched" if len(ids) == 1 else "ambiguous", ids)


def correlate_runtime_indirect_calls(
    graph: dict[str, Any], *, graph_sha256: str,
    static_identity: dict[str, Any], static_identity_sha256: str,
    capture: dict[str, Any], capture_sha256: str,
    observations: list[dict[str, Any]], observations_sha256: str,
) -> dict[str, Any]:
    """Join exact runtime caller/site/target triples without promoting static candidates."""
    _digest(graph_sha256, "semantic graph SHA-256")
    _digest(static_identity_sha256, "static identity SHA-256")
    _digest(capture_sha256, "capture manifest SHA-256")
    _digest(observations_sha256, "runtime observations SHA-256")
    identity = _read_static_identity(static_identity)
    capture = _read_capture(capture)
    observations = _validate_indirect_observations(observations, capture)
    if graph.get("format") != FORMAT_V3:
        raise ValueError("runtime indirect-call correlation requires SemanticProgramGraph/3")
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
    address_delta = capture["_runtime_module_base"] - identity["_static_image_base"]

    functions_by_entry: dict[str, list[dict[str, Any]]] = {}
    callsites: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for node in graph["nodes"]:
        if node.get("kind") == "function":
            entry, _ = _normalize(node["entry"], 0)
            functions_by_entry.setdefault(entry, []).append(node)
        elif node.get("kind") == "operation" and node.get("opcode") == "CALLIND":
            owner, _ = _normalize(node["function_entry"], 0)
            address, _ = _normalize(node["operation_address"], 0)
            callsites.setdefault((owner, address), []).append(node)

    events = []
    counts: Counter[str] = Counter()
    for row in observations:
        caller_address, caller_mapping = _normalize(row["caller_runtime_address"], address_delta)
        site_address, site_mapping = _normalize(row["callsite_runtime_address"], address_delta)
        target_address, target_mapping = _normalize(row["target_runtime_address"], address_delta)

        caller_nodes = functions_by_entry.get(caller_address, []) if caller_address is not None else []
        caller_state, caller_ids = _match(caller_nodes) if caller_mapping == "mapped" else (caller_mapping, [])
        site_nodes = callsites.get((caller_address, site_address), []) if caller_address is not None and site_address is not None else []
        if site_mapping != "mapped":
            site_state, site_ids = site_mapping, []
        else:
            site_state, site_ids = _match(site_nodes)
        target_nodes = functions_by_entry.get(target_address, []) if target_address is not None else []
        target_state, target_ids = _match(target_nodes) if target_mapping == "mapped" else (target_mapping, [])

        if caller_state in {"mapping_underflow", "mapping_overflow"}:
            state = caller_state
        elif site_state in {"mapping_underflow", "mapping_overflow"}:
            state = site_state
        elif caller_state != "matched":
            state = f"{caller_state}_caller"
        elif site_state != "matched":
            state = f"{site_state}_callsite"
        elif target_state in {"mapping_underflow", "mapping_overflow"}:
            state = target_state
        elif target_state != "matched":
            state = f"{target_state}_target"
        else:
            state = "matched"
        counts[state] += 1
        events.append({
            "capture_id": capture["capture_id"],
            "sequence": row["sequence"],
            "caller_runtime_address": row["caller_runtime_address"],
            "callsite_runtime_address": row["callsite_runtime_address"],
            "target_runtime_address": row["target_runtime_address"],
            "caller_address": caller_address,
            "callsite_address": site_address,
            "target_address": target_address,
            "caller_match_state": caller_state,
            "callsite_match_state": site_state,
            "target_match_state": target_state,
            "caller_node_ids": caller_ids,
            "callsite_node_ids": site_ids,
            "target_node_ids": target_ids,
            "match_state": state,
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
        "address_mapping": {
            "method": "runtime_address_minus_module_delta",
            "runtime_module_base": capture["runtime_module_base"],
            "static_image_base": identity["static_image_base"],
            "module_delta": _signed_hex(address_delta),
        },
        "sampling": {"status": capture["sampling_status"], "gaps": capture["sampling_gaps"]},
        "summary": {"event_count": len(events), "match_state_counts": dict(sorted(counts.items()))},
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
        raise ValueError("runtime indirect-call correlation requires exactly one semantic graph")
    identity, identity_sha256 = _read_runtime_json(args.static_identity)
    capture, capture_sha256 = _read_runtime_json(args.capture_manifest)
    observations, observations_sha256 = _read_observations(args.observations)
    report = correlate_runtime_indirect_calls(
        graphs[0], graph_sha256=graph_sha256,
        static_identity=identity, static_identity_sha256=identity_sha256,
        capture=capture, capture_sha256=capture_sha256,
        observations=observations, observations_sha256=observations_sha256,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("runtime indirect calls:", report["summary"]["event_count"])
    print("match states:", report["summary"]["match_state_counts"])
    print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
