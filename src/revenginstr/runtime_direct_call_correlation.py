"""Correlate bounded runtime direct-call sites and targets with a pinned graph."""
from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path
from typing import Any

from revenginstr.runtime_static_correlation import (
    MAX_EVENTS,
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
    FORMAT_V4,
    _read_jsonl,
    validate_graph_references,
)

OBSERVATION_FORMAT = "REVENGINSTR.RuntimeDirectCallObservation/1"
REPORT_FORMAT = "REVENGINSTR.RuntimeDirectCallCorrelation/1"


def _read_observations(path: Path) -> tuple[list[dict[str, Any]], str]:
    if path.stat().st_size > 64 * 1024 * 1024:
        raise ValueError(f"{path}: input exceeds 64 MiB")
    rows, digest = _read_jsonl(path)
    if not 1 <= len(rows) <= MAX_EVENTS:
        raise ValueError(f"runtime direct-call observations must contain 1 to {MAX_EVENTS} rows")
    return rows, digest


def _validate_direct_observations(
    rows: list[dict[str, Any]], capture: dict[str, Any],
) -> list[dict[str, Any]]:
    if not 1 <= len(rows) <= MAX_EVENTS:
        raise ValueError(f"runtime direct-call observations must contain 1 to {MAX_EVENTS} rows")
    capture_id = capture["capture_id"]
    validated = []
    for index, row in enumerate(rows, 1):
        where = f"observation {index}"
        if set(row) != {
            "format", "capture_id", "sequence", "callsite_runtime_address", "target_runtime_address",
        }:
            raise ValueError(f"{where}: unexpected fields")
        if row["format"] != OBSERVATION_FORMAT or row["capture_id"] != capture_id:
            raise ValueError(f"{where}: wrong format or capture_id")
        sequence = row["sequence"]
        if isinstance(sequence, bool) or not isinstance(sequence, int) or not 0 <= sequence <= 1_000_000_000:
            raise ValueError(f"{where}: invalid sequence")
        for key in ("callsite_runtime_address", "target_runtime_address"):
            _address(row[key], f"{where} {key}")
        validated.append(row)

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


def _match(nodes: list[dict[str, Any]]) -> tuple[str, list[str]]:
    ids = sorted(node["id"] for node in nodes)
    return ("unmatched" if not ids else "matched" if len(ids) == 1 else "ambiguous", ids)


def _normalize(address: str, delta: int) -> tuple[str | None, str]:
    normalized = _address(address, "runtime address") - delta
    if normalized < 0:
        return None, "mapping_underflow"
    if normalized > (1 << 64) - 1:
        return None, "mapping_overflow"
    return f"0x{normalized:x}", "mapped"


def correlate_runtime_direct_calls(
    graph: dict[str, Any], *, graph_sha256: str,
    static_identity: dict[str, Any], static_identity_sha256: str,
    capture: dict[str, Any], capture_sha256: str,
    observations: list[dict[str, Any]], observations_sha256: str,
) -> dict[str, Any]:
    """Join runtime callsite/target observations to one exact direct CALL edge."""
    _digest(graph_sha256, "semantic graph SHA-256")
    _digest(static_identity_sha256, "static identity SHA-256")
    _digest(capture_sha256, "capture manifest SHA-256")
    _digest(observations_sha256, "runtime observations SHA-256")
    identity = _read_static_identity(static_identity)
    capture = _read_capture(capture)
    observations = _validate_direct_observations(observations, capture)
    if graph.get("format") not in {FORMAT_V3, FORMAT_V4}:
        raise ValueError("runtime direct-call correlation requires SemanticProgramGraph/3 or /4")
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

    functions: dict[str, list[dict[str, Any]]] = {}
    callsites: dict[str, list[dict[str, Any]]] = {}
    call_edges = {
        (edge["from"], edge["to"])
        for edge in graph["edges"] if edge.get("relation") == "calls"
    }
    for node in graph["nodes"]:
        if node.get("kind") == "function":
            entry, _ = _normalize(node["entry"], 0)
            functions.setdefault(entry, []).append(node)
        elif node.get("kind") == "operation" and node.get("opcode") == "CALL":
            address, _ = _normalize(node["operation_address"], 0)
            callsites.setdefault(address, []).append(node)

    events = []
    counts: Counter[str] = Counter()
    for row in observations:
        site_address, site_mapping = _normalize(row["callsite_runtime_address"], address_delta)
        target_address, target_mapping = _normalize(row["target_runtime_address"], address_delta)
        site_nodes = callsites.get(site_address, []) if site_address is not None else []
        site_state, site_ids = _match(site_nodes) if site_mapping == "mapped" else (site_mapping, [])
        target_nodes = functions.get(target_address, []) if target_address is not None else []
        target_state, target_ids = _match(target_nodes) if target_mapping == "mapped" else (target_mapping, [])

        caller_entries = sorted({
            _normalize(node["function_entry"], 0)[0]
            for node in site_nodes if isinstance(node.get("function_entry"), str)
        })
        caller_nodes = [node for entry in caller_entries for node in functions.get(entry, [])]
        caller_state, caller_ids = _match(caller_nodes)
        static_targets = sorted({entry for node in site_nodes for entry in node.get("target_entries", []) if isinstance(entry, str)})
        if not site_nodes:
            static_target_state = "unavailable"
        elif len(static_targets) != 1:
            static_target_state = "unresolved" if not static_targets else "ambiguous"
        elif target_address is None:
            static_target_state = target_mapping
        else:
            static_target_nodes = functions.get(_normalize(static_targets[0], 0)[0], [])
            static_target_state = (
                "matched"
                if _address(static_targets[0], "static direct-call target") == int(target_address, 16)
                and len(site_nodes) == 1 and len(target_nodes) == 1
                and len(static_target_nodes) == 1
                and static_target_nodes[0]["id"] == target_nodes[0]["id"]
                and (site_nodes[0]["id"], target_nodes[0]["id"]) in call_edges
                else "mismatch"
            )

        if site_state in {"mapping_underflow", "mapping_overflow"}:
            state = site_state
        elif site_state != "matched":
            state = f"{site_state}_callsite"
        elif caller_state != "matched":
            state = f"{caller_state}_caller"
        elif target_state in {"mapping_underflow", "mapping_overflow"}:
            state = target_state
        elif target_state != "matched":
            state = f"{target_state}_target"
        elif static_target_state != "matched":
            state = f"static_target_{static_target_state}"
        else:
            state = "matched"
        counts[state] += 1
        events.append({
            "capture_id": capture["capture_id"],
            "sequence": row["sequence"],
            "callsite_runtime_address": row["callsite_runtime_address"],
            "target_runtime_address": row["target_runtime_address"],
            "callsite_address": site_address,
            "caller_addresses": caller_entries,
            "target_address": target_address,
            "callsite_match_state": site_state,
            "caller_match_state": caller_state,
            "target_match_state": target_state,
            "static_target_match_state": static_target_state,
            "callsite_node_ids": site_ids,
            "caller_node_ids": caller_ids,
            "target_node_ids": target_ids,
            "static_target_entries": static_targets,
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
        raise ValueError("runtime direct-call correlation requires exactly one semantic graph")
    identity, identity_sha256 = _read_runtime_json(args.static_identity)
    capture, capture_sha256 = _read_runtime_json(args.capture_manifest)
    observations, observations_sha256 = _read_observations(args.observations)
    report = correlate_runtime_direct_calls(
        graphs[0], graph_sha256=graph_sha256,
        static_identity=identity, static_identity_sha256=identity_sha256,
        capture=capture, capture_sha256=capture_sha256,
        observations=observations, observations_sha256=observations_sha256,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("runtime direct calls:", report["summary"]["event_count"])
    print("match states:", report["summary"]["match_state_counts"])
    print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
