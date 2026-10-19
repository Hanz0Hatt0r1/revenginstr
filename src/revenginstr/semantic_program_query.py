"""Run deterministic, provenance-preserving queries over semantic graphs."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from revenginstr.semantic_program_graph import (
    FORMAT_V1,
    FORMAT_V2,
    FORMAT_V3,
    _read_jsonl,
    validate_graph_references,
)

FORMAT = "REVENGINSTR.SemanticProgramQueryResult/1"
VIEWS = ("exact-only", "accepted-high-confidence", "exploratory")
NODE_KINDS = ("program", "function", "operation", "field", "receiver_observation", "type", "layout_field")
RELATIONS = ("contains", "calls", "reads", "writes", "observes_receiver", "has_field")
CALL_STATES = ("not_applicable", "resolved", "unresolved", "indirect", "conflicted")


def _in_view(row: dict[str, Any], view: str, minimum_confidence: float) -> bool:
    if view == "exploratory":
        return True
    if view == "exact-only":
        return row.get("evidence_class") == "exact_static"
    if row.get("conflict_state") != "uncontested":
        return False
    if row.get("evidence_class") == "exact_static":
        return True
    confidence = row.get("confidence")
    return (
        isinstance(confidence, (int, float))
        and not isinstance(confidence, bool)
        and confidence >= minimum_confidence
    )


def _supports(row: dict[str, Any], support_id: str | None) -> bool:
    if support_id is None:
        return True
    return any(
        support.get("effect_id") == support_id
        or support.get("source_record_id") == support_id
        for support in row.get("support", [])
    )


def _matches_node(row: dict[str, Any], filters: dict[str, Any]) -> bool:
    if filters["kinds"] and row.get("kind") not in filters["kinds"]:
        return False
    if filters["call_target_states"] and row.get("call_target_state") not in filters["call_target_states"]:
        return False
    if filters["conflict_state"] != "any" and row.get("conflict_state") != filters["conflict_state"]:
        return False
    if filters["function_entries"] and not any(
        row.get(field) in filters["function_entries"]
        for field in ("entry", "function_entry", "owner_function_entry")
    ):
        return False
    if filters["operation_addresses"] and row.get("operation_address") not in filters["operation_addresses"]:
        return False
    if filters["field_offsets"] and row.get("field_offset") not in filters["field_offsets"]:
        if not (
            isinstance(row.get("offset_bytes"), int)
            and f"0x{row['offset_bytes']:x}" in filters["field_offsets"]
        ):
            return False
    if filters["type_ids"] and row.get("type_id") not in filters["type_ids"]:
        return False
    return _supports(row, filters["support_id"])


def _matches_edge(row: dict[str, Any], filters: dict[str, Any]) -> bool:
    if filters["relations"] and row.get("relation") not in filters["relations"]:
        return False
    if filters["conflict_state"] != "any" and row.get("conflict_state") != filters["conflict_state"]:
        return False
    return _supports(row, filters["support_id"])


def query_graphs(
    graphs: list[dict[str, Any]],
    *,
    source_sha256: str,
    view: str = "exploratory",
    minimum_confidence: float = 0.95,
    kinds: list[str] | None = None,
    relations: list[str] | None = None,
    call_target_states: list[str] | None = None,
    conflict_state: str = "any",
    function_entries: list[str] | None = None,
    operation_addresses: list[str] | None = None,
    field_offsets: list[str] | None = None,
    type_ids: list[str] | None = None,
    support_id: str | None = None,
) -> list[dict[str, Any]]:
    """Return matching graph facts and endpoint context with source provenance."""
    if view not in VIEWS:
        raise ValueError(f"unsupported query view: {view!r}")
    if not 0 <= minimum_confidence <= 1:
        raise ValueError("minimum_confidence must be between 0 and 1")
    if len(source_sha256) != 64 or any(char not in "0123456789abcdef" for char in source_sha256):
        raise ValueError("source_sha256 must be a lowercase SHA-256 digest")
    if conflict_state not in {"any", "uncontested", "contested"}:
        raise ValueError(f"unsupported conflict state: {conflict_state!r}")
    if set(kinds or []) - set(NODE_KINDS):
        raise ValueError("unsupported node kind filter")
    if set(relations or []) - set(RELATIONS):
        raise ValueError("unsupported edge relation filter")
    if set(call_target_states or []) - set(CALL_STATES):
        raise ValueError("unsupported call target state filter")
    if not graphs:
        raise ValueError("Semantic Program Graph input is empty")
    filters = {
        "kinds": sorted(set(kinds or [])),
        "relations": sorted(set(relations or [])),
        "call_target_states": sorted(set(call_target_states or [])),
        "conflict_state": conflict_state,
        "function_entries": sorted(set(function_entries or [])),
        "operation_addresses": sorted(set(operation_addresses or [])),
        "field_offsets": sorted(set(field_offsets or [])),
        "type_ids": sorted(set(type_ids or [])),
        "support_id": support_id,
    }
    node_filters_active = any((
        filters["kinds"], filters["call_target_states"],
        filters["function_entries"], filters["operation_addresses"],
        filters["field_offsets"], filters["type_ids"], filters["support_id"],
    ))

    results = []
    seen_graph_ids: set[str] = set()
    for graph in graphs:
        if graph.get("format") not in {FORMAT_V1, FORMAT_V2, FORMAT_V3}:
            raise ValueError(f"unsupported graph format: {graph.get('format')!r}")
        if graph["graph_id"] in seen_graph_ids:
            raise ValueError(f"duplicate semantic program graph id: {graph['graph_id']!r}")
        seen_graph_ids.add(graph["graph_id"])
        validate_graph_references(graph)
        selected_nodes = [
            node for node in graph["nodes"]
            if _in_view(node, view, minimum_confidence) and _matches_node(node, filters)
        ]
        selected_ids = {node["id"] for node in selected_nodes}
        candidate_edges = [
            edge for edge in graph["edges"]
            if _in_view(edge, view, minimum_confidence)
            and _matches_edge(edge, filters)
        ]
        if node_filters_active:
            selected_edges = [
                edge for edge in candidate_edges
                if edge["from"] in selected_ids or edge["to"] in selected_ids
            ]
        elif filters["relations"]:
            matched_endpoint_ids = {
                endpoint
                for edge in candidate_edges
                for endpoint in (edge["from"], edge["to"])
            }
            selected_nodes = [
                node for node in graph["nodes"]
                if node["id"] in matched_endpoint_ids
                and _in_view(node, view, minimum_confidence)
            ]
            selected_ids = {node["id"] for node in selected_nodes}
            selected_edges = candidate_edges
        else:
            selected_edges = candidate_edges
        endpoint_ids = {
            endpoint
            for edge in selected_edges
            for endpoint in (edge["from"], edge["to"])
        }
        nodes_by_id = {node["id"]: node for node in graph["nodes"]}
        related_nodes = [
            nodes_by_id[node_id]
            for node_id in sorted(endpoint_ids - selected_ids)
        ]
        query_identity = {
            "source_graph_id": graph["graph_id"],
            "source_graph_sha256": source_sha256,
            "view": view,
            "minimum_confidence": minimum_confidence,
            "filters": filters,
        }
        query_id = "query:" + hashlib.sha256(
            json.dumps(query_identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        results.append({
            "format": FORMAT,
            "query_id": query_id,
            "source_graph_id": graph["graph_id"],
            "source_graph_format": graph["format"],
            "program_id": graph["program_id"],
            "source_graph_sha256": source_sha256,
            "view": view,
            "minimum_confidence": minimum_confidence,
            "filters": filters,
            "nodes": selected_nodes,
            "related_nodes": related_nodes,
            "edges": selected_edges,
        })
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("semantic_program_graph", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--view", choices=VIEWS, default="exploratory")
    parser.add_argument("--minimum-confidence", type=float, default=0.95)
    parser.add_argument("--kind", action="append", choices=NODE_KINDS, default=[])
    parser.add_argument("--relation", action="append", choices=RELATIONS, default=[])
    parser.add_argument("--call-target-state", action="append", choices=CALL_STATES, default=[])
    parser.add_argument("--conflict-state", choices=("any", "uncontested", "contested"), default="any")
    parser.add_argument("--function-entry", action="append", default=[])
    parser.add_argument("--operation-address", action="append", default=[])
    parser.add_argument("--field-offset", action="append", default=[])
    parser.add_argument("--type-id", action="append", default=[])
    parser.add_argument("--support-id")
    args = parser.parse_args(argv)
    try:
        graphs, source_sha256 = _read_jsonl(args.semantic_program_graph)
        results = query_graphs(
            graphs,
            source_sha256=source_sha256,
            view=args.view,
            minimum_confidence=args.minimum_confidence,
            kinds=args.kind,
            relations=args.relation,
            call_target_states=args.call_target_state,
            conflict_state=args.conflict_state,
            function_entries=args.function_entry,
            operation_addresses=args.operation_address,
            field_offsets=args.field_offset,
            type_ids=args.type_id,
            support_id=args.support_id,
        )
    except ValueError as error:
        parser.error(str(error))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for result in results:
            handle.write(json.dumps(result, sort_keys=True) + "\n")
    print("program graphs queried:", len(results))
    print("matched nodes:", sum(len(row["nodes"]) for row in results))
    print("related nodes:", sum(len(row["related_nodes"]) for row in results))
    print("matched edges:", sum(len(row["edges"]) for row in results))
    print("query:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
