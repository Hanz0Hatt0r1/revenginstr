"""Find bounded direct-call paths and optionally annotate call sites with CFG evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import deque
from pathlib import Path
from typing import Any

from revenginstr.semantic_program_graph import (
    FORMAT_V1,
    FORMAT_V2,
    FORMAT_V3,
    _read_jsonl,
    validate_graph_references,
)
from revenginstr.semantic_program_query import VIEWS, _in_view
from revenginstr.receiver.field_flow import _index_cfg

FORMAT = "REVENGINSTR.SemanticProgramPathQueryResult/1"
CALL_STATES = {"indirect", "unresolved", "conflicted"}


def _consume_expansion(budget: list[int], max_expansions: int) -> None:
    budget[0] += 1
    if budget[0] > max_expansions:
        raise ValueError(
            f"query exceeded --max-expansions ({max_expansions}); no partial result written"
        )


def _reachable_block_paths(
    cfg: dict[str, Any], *, max_expansions: int, expansion_budget: list[int]
) -> dict[int, list[int]]:
    entry = cfg["entry_block_index"]
    blocks = cfg["blocks"]
    paths = {entry: [entry]}
    pending = deque([entry])
    while pending:
        block_index = pending.popleft()
        for successor in sorted(blocks[block_index]["successors"]):
            _consume_expansion(expansion_budget, max_expansions)
            if successor not in paths:
                paths[successor] = [*paths[block_index], successor]
                pending.append(successor)
    return paths


def _cfg_callsite(
    program_id: str,
    function_entry: str,
    operation: dict[str, Any],
    *,
    cfg_index: dict[tuple[str, str], tuple[int, dict[str, Any]]],
    reachability_cache: dict[tuple[str, str], dict[int, list[int]] | None],
    max_expansions: int,
    expansion_budget: list[int],
) -> dict[str, Any]:
    cfg_item = cfg_index.get((program_id, function_entry))
    if cfg_item is None:
        return {
            "status": "function_cfg_missing",
            "cfg_record_index": None,
            "block_index": None,
            "block_path": [],
        }
    record_index, cfg = cfg_item
    operation_key = (operation.get("operation_address"), operation.get("operation_time"))
    location = cfg["operations"].get(operation_key)
    if location is None:
        return {
            "status": "operation_missing",
            "cfg_record_index": record_index,
            "block_index": None,
            "block_path": [],
        }
    block_index, _position, opcode = location
    if opcode != operation.get("opcode"):
        status = "opcode_mismatch"
        block_path = []
    elif cfg["entry_block_index"] is None:
        status = "entry_block_unavailable"
        block_path = []
    else:
        cache_key = (program_id, function_entry)
        if cache_key not in reachability_cache:
            reachability_cache[cache_key] = _reachable_block_paths(
                cfg, max_expansions=max_expansions, expansion_budget=expansion_budget
            )
        block_path = reachability_cache[cache_key].get(block_index) or []
        status = "reachable" if block_path else "unreachable"
    return {
        "status": status,
        "cfg_record_index": record_index,
        "block_index": block_index,
        "block_path": block_path,
    }


def _annotate_cfg_step(
    step: dict[str, Any],
    program_id: str,
    *,
    cfg_index: dict[tuple[str, str], tuple[int, dict[str, Any]]],
    reachability_cache: dict[tuple[str, str], dict[int, list[int]]],
    max_expansions: int,
    expansion_budget: list[int],
) -> None:
    if "cfg_callsite" not in step:
        step["cfg_callsite"] = _cfg_callsite(
            program_id,
            step["caller_entry"],
            step["call_operation"],
            cfg_index=cfg_index,
            reachability_cache=reachability_cache,
            max_expansions=max_expansions,
            expansion_budget=expansion_budget,
        )


def _call_transitions(
    graph: dict[str, Any],
    *,
    view: str,
    minimum_confidence: float,
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, dict[str, Any]]]:
    nodes = {node["id"]: node for node in graph["nodes"]}
    functions = {
        node["entry"]: node
        for node in graph["nodes"]
        if node["kind"] == "function"
    }
    memberships = {
        (edge["from"], edge["to"]): edge
        for edge in graph["edges"]
        if edge["relation"] == "contains"
    }
    transitions: dict[str, list[dict[str, Any]]] = {entry: [] for entry in functions}
    for call_edge in graph["edges"]:
        if call_edge["relation"] != "calls":
            continue
        operation = nodes[call_edge["from"]]
        callee = nodes[call_edge["to"]]
        if operation.get("call_target_state") not in {"resolved", "conflicted"}:
            continue
        caller_entry = operation.get("function_entry")
        callee_entry = callee.get("entry")
        caller = functions.get(caller_entry)
        membership = memberships.get((caller["id"], operation["id"])) if caller else None
        if caller is None or callee_entry is None or membership is None:
            raise ValueError(
                f"call edge {call_edge['id']!r} has no function/operation membership context"
            )
        callee_function = functions.get(callee_entry)
        if callee_function is None:
            raise ValueError(
                f"call edge {call_edge['id']!r} targets a missing function node"
            )
        if not all(
            _in_view(row, view, minimum_confidence)
            for row in (call_edge, operation, membership)
        ):
            continue
        if view == "accepted-high-confidence" and any(
            row.get("conflict_state") == "contested" for row in (caller, callee_function)
        ):
            continue
        conflict_state = (
            "contested"
            if any(row.get("conflict_state") == "contested" for row in (
                call_edge, operation, membership, caller, callee_function
            ))
            else "uncontested"
        )
        transition = {
            "caller_entry": caller_entry,
            "caller_function": caller,
            "call_operation": operation,
            "membership_edge": membership,
            "call_edge": call_edge,
            "callee_entry": callee_entry,
            "callee_function": callee_function,
            "conflict_state": conflict_state,
        }
        transitions[caller_entry].append(transition)
    for outgoing in transitions.values():
        outgoing.sort(key=lambda step: (
            step["callee_entry"],
            step["call_operation"].get("operation_address", ""),
            step["call_operation"].get("operation_time", -1),
            step["call_edge"]["id"],
        ))
    return transitions, functions


def _enumerate_paths(
    transitions: dict[str, list[dict[str, Any]]],
    source_entry: str,
    target_entry: str,
    *,
    max_hops: int,
    max_paths: int,
    max_expansions: int,
    expansion_budget: list[int],
) -> list[dict[str, Any]]:
    if source_entry == target_entry:
        return [{
            "function_entries": [source_entry],
            "steps": [],
            "conflict_state": "uncontested",
        }]
    paths = []
    pending = [(source_entry, [source_entry], [])]
    while pending:
        current, entries, steps = pending.pop()
        if len(steps) >= max_hops:
            continue
        for step in reversed(transitions.get(current, [])):
            _consume_expansion(expansion_budget, max_expansions)
            next_entry = step["callee_entry"]
            if next_entry in entries:
                continue
            next_entries = [*entries, next_entry]
            next_steps = [*steps, step]
            if next_entry == target_entry:
                paths.append({
                    "function_entries": next_entries,
                    "steps": next_steps,
                    "conflict_state": (
                        "contested"
                        if any(row["conflict_state"] == "contested" for row in next_steps)
                        else "uncontested"
                    ),
                })
                if len(paths) > max_paths:
                    raise ValueError(
                        f"path search exceeded --max-paths ({max_paths}); no partial result written"
                    )
            else:
                pending.append((next_entry, next_entries, next_steps))
    return paths


def _reachable_witnesses(
    transitions: dict[str, list[dict[str, Any]]],
    source_entry: str,
    *,
    max_hops: int,
    max_expansions: int,
    expansion_budget: list[int],
    source_conflict_state: str,
) -> dict[str, dict[str, Any]]:
    def paths(*, uncontested_only: bool) -> dict[str, tuple[int, list[dict[str, Any]]]]:
        reached = {source_entry: (0, [])}
        pending = deque([source_entry])
        while pending:
            entry = pending.popleft()
            depth, witness = reached[entry]
            if depth >= max_hops:
                continue
            for step in transitions.get(entry, []):
                _consume_expansion(expansion_budget, max_expansions)
                if uncontested_only and step["conflict_state"] == "contested":
                    continue
                target = step["callee_entry"]
                if target not in reached:
                    reached[target] = (depth + 1, [*witness, step])
                    pending.append(target)
        return reached

    any_path = paths(uncontested_only=False)
    clean_path = paths(uncontested_only=True)
    return {
        entry: {
            "conflict_state": (
                "uncontested"
                if entry in clean_path and source_conflict_state != "contested"
                else "contested"
            ),
            "steps": clean_path[entry][1] if entry in clean_path else any_path[entry][1],
        }
        for entry in any_path
    }


def _path_cfg_status(path: dict[str, Any]) -> str:
    statuses = [step["cfg_callsite"]["status"] for step in path["steps"]]
    if not statuses:
        return "no_call_sites_to_check"
    if "opcode_mismatch" in statuses:
        return "cfg_opcode_mismatch"
    if any(status not in {"reachable", "unreachable"} for status in statuses):
        return "incomplete_cfg_evidence"
    if "unreachable" in statuses:
        return "contains_unreachable_call_site"
    return "all_call_sites_in_entry_reachable_blocks"


def query_graphs(
    graphs: list[dict[str, Any]],
    *,
    source_sha256: str,
    source_function_entry: str,
    target_function_entry: str,
    view: str = "exact-only",
    minimum_confidence: float = 0.95,
    max_hops: int = 12,
    max_paths: int = 100,
    max_expansions: int = 10000,
    cfg_index: dict[tuple[str, str], tuple[int, dict[str, Any]]] | None = None,
    cfg_sha256: str | None = None,
) -> list[dict[str, Any]]:
    """Enumerate bounded simple paths made only from evidence-backed calls edges."""
    if view not in VIEWS:
        raise ValueError(f"unsupported query view: {view!r}")
    if not 0 <= minimum_confidence <= 1:
        raise ValueError("minimum_confidence must be between 0 and 1")
    if len(source_sha256) != 64 or any(char not in "0123456789abcdef" for char in source_sha256):
        raise ValueError("source_sha256 must be a lowercase SHA-256 digest")
    if cfg_index is not None and (
        cfg_sha256 is None
        or len(cfg_sha256) != 64
        or any(char not in "0123456789abcdef" for char in cfg_sha256)
    ):
        raise ValueError("CFG input requires its lowercase SHA-256 digest")
    if cfg_index is None and cfg_sha256 is not None:
        raise ValueError("CFG SHA-256 supplied without indexed CFG records")
    if cfg_index is not None and not cfg_index:
        raise ValueError("CFG input is empty")
    if not source_function_entry or not target_function_entry:
        raise ValueError("source and target function entries must be non-empty")
    if max_hops < 0 or max_paths < 1 or max_expansions < 1:
        raise ValueError("path bounds require max_hops >= 0 and positive max_paths/max_expansions")
    if not graphs:
        raise ValueError("Semantic Program Graph input is empty")

    results = []
    seen_graph_ids: set[str] = set()
    for graph in graphs:
        if graph.get("format") not in {FORMAT_V1, FORMAT_V2, FORMAT_V3}:
            raise ValueError(f"unsupported graph format: {graph.get('format')!r}")
        graph_id = graph["graph_id"]
        if graph_id in seen_graph_ids:
            raise ValueError(f"duplicate semantic program graph id: {graph_id!r}")
        seen_graph_ids.add(graph_id)
        validate_graph_references(graph)
        expansion_budget = [0]
        cfg_reachability_cache: dict[tuple[str, str], dict[int, list[int]]] = {}
        if cfg_index is not None and not any(
            program_id == graph["program_id"] for program_id, _entry in cfg_index
        ):
            raise ValueError(
                f"CFG program id does not match graph program id {graph['program_id']!r}"
            )
        transitions, functions = _call_transitions(
            graph,
            view=view,
            minimum_confidence=minimum_confidence,
        )
        source_found = source_function_entry in functions
        target_found = target_function_entry in functions
        if not source_found and not target_found:
            status = "both_functions_missing"
        elif not source_found:
            status = "source_function_missing"
        elif not target_found:
            status = "target_function_missing"
        else:
            status = "no_direct_call_path_within_bound"
        paths = []
        frontier = []
        if source_found and target_found:
            if source_function_entry == target_function_entry:
                identity_in_view = _in_view(functions[source_function_entry], view, minimum_confidence)
            else:
                identity_in_view = True
            if identity_in_view:
                paths = _enumerate_paths(
                    transitions,
                    source_function_entry,
                    target_function_entry,
                    max_hops=max_hops,
                    max_paths=max_paths,
                    max_expansions=max_expansions,
                    expansion_budget=expansion_budget,
                )
                if cfg_index is not None:
                    for path in paths:
                        for step in path["steps"]:
                            _annotate_cfg_step(
                                step,
                                graph["program_id"],
                                cfg_index=cfg_index,
                                reachability_cache=cfg_reachability_cache,
                                max_expansions=max_expansions,
                                expansion_budget=expansion_budget,
                            )
                        path["cfg_status"] = _path_cfg_status(path)
            if paths:
                status = "direct_call_paths_found"
        source_function = functions.get(source_function_entry)
        if source_found and (
            view != "accepted-high-confidence"
            or _in_view(source_function, view, minimum_confidence)
        ):
            reachable = _reachable_witnesses(
                transitions,
                source_function_entry,
                max_hops=max_hops,
                max_expansions=max_expansions,
                expansion_budget=expansion_budget,
                source_conflict_state=source_function.get("conflict_state", "uncontested"),
            )
            memberships = {
                (edge["from"], edge["to"]): edge
                for edge in graph["edges"]
                if edge["relation"] == "contains"
            }
            frontier = []
            for node in graph["nodes"]:
                if node["kind"] != "operation" or node.get("call_target_state") not in CALL_STATES:
                    continue
                entry = node.get("function_entry")
                function = functions.get(entry)
                witness = reachable.get(entry)
                membership = memberships.get((function["id"], node["id"])) if function else None
                if (
                    witness is None
                    or membership is None
                    or not _in_view(node, view, minimum_confidence)
                    or not _in_view(membership, view, minimum_confidence)
                ):
                    continue
                frontier_row = {
                    "function_entry": entry,
                    "reachable_with_conflict_state": witness["conflict_state"],
                    "reachability_steps": witness["steps"],
                    "function": function,
                    "membership_edge": membership,
                    "operation": node,
                }
                if cfg_index is not None:
                    for step in frontier_row["reachability_steps"]:
                        _annotate_cfg_step(
                            step,
                            graph["program_id"],
                            cfg_index=cfg_index,
                            reachability_cache=cfg_reachability_cache,
                            max_expansions=max_expansions,
                            expansion_budget=expansion_budget,
                        )
                    frontier_row["cfg_callsite"] = _cfg_callsite(
                        graph["program_id"], entry, node,
                        cfg_index=cfg_index,
                        reachability_cache=cfg_reachability_cache,
                        max_expansions=max_expansions,
                        expansion_budget=expansion_budget,
                    )
                frontier.append(frontier_row)
            frontier.sort(key=lambda row: (
                row["function_entry"],
                row["operation"].get("operation_address", ""),
                row["operation"].get("operation_time", -1),
                row["operation"]["id"],
            ))

        identity = {
            "source_graph_id": graph_id,
            "source_graph_sha256": source_sha256,
            "source_function_entry": source_function_entry,
            "target_function_entry": target_function_entry,
            "view": view,
            "minimum_confidence": minimum_confidence,
            "max_hops": max_hops,
            "max_paths": max_paths,
            "max_expansions": max_expansions,
        }
        if cfg_sha256 is not None:
            identity["cfg_source_sha256"] = cfg_sha256
        query_id = "path-query:" + hashlib.sha256(
            json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        result = {
            "format": FORMAT,
            "query_id": query_id,
            "source_graph_id": graph_id,
            "source_graph_format": graph["format"],
            "program_id": graph["program_id"],
            "source_graph_sha256": source_sha256,
            "source_function_entry": source_function_entry,
            "target_function_entry": target_function_entry,
            "view": view,
            "minimum_confidence": minimum_confidence,
            "max_hops": max_hops,
            "max_paths": max_paths,
            "max_expansions": max_expansions,
            "path_semantics": "exact_direct_call_graph_only",
            "status": status,
            "paths": paths,
            "uncertain_call_frontier": frontier,
        }
        if cfg_sha256 is not None:
            result["cfg_source_sha256"] = cfg_sha256
            result["cfg_semantics"] = "entry_block_successor_reachability"
        results.append(result)
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("semantic_program_graph", type=Path)
    parser.add_argument("--source-function-entry", required=True)
    parser.add_argument("--target-function-entry", required=True)
    parser.add_argument("--view", choices=VIEWS, default="exact-only")
    parser.add_argument("--minimum-confidence", type=float, default=0.95)
    parser.add_argument("--max-hops", type=int, default=12)
    parser.add_argument("--max-paths", type=int, default=100)
    parser.add_argument("--max-expansions", type=int, default=10000)
    parser.add_argument("--function-pcode-cfg", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        graphs, source_sha256 = _read_jsonl(args.semantic_program_graph)
        cfg_index = None
        cfg_sha256 = None
        if args.function_pcode_cfg is not None:
            cfg_records, cfg_sha256 = _read_jsonl(args.function_pcode_cfg)
            cfg_index = _index_cfg(cfg_records)
        results = query_graphs(
            graphs,
            source_sha256=source_sha256,
            source_function_entry=args.source_function_entry,
            target_function_entry=args.target_function_entry,
            view=args.view,
            minimum_confidence=args.minimum_confidence,
            max_hops=args.max_hops,
            max_paths=args.max_paths,
            max_expansions=args.max_expansions,
            cfg_index=cfg_index,
            cfg_sha256=cfg_sha256,
        )
    except ValueError as error:
        parser.error(str(error))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for result in results:
            handle.write(json.dumps(result, sort_keys=True) + "\n")
    print("program graphs queried:", len(results))
    print("direct-call paths:", sum(len(row["paths"]) for row in results))
    print("uncertain call frontier sites:", sum(len(row["uncertain_call_frontier"]) for row in results))
    if args.function_pcode_cfg is not None:
        print("CFG artifact SHA-256:", cfg_sha256)
    print("query:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
