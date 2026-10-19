"""Evaluate scoped semantic-graph edges against adjudicated consumer gold."""
from __future__ import annotations

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from revenginstr.semantic_program_graph import (
    FORMAT_V1,
    FORMAT_V2,
    FORMAT_V3,
    _read_jsonl,
    _valid_edge_endpoints,
    validate_graph_references,
)
from revenginstr.semantic_program_query import RELATIONS, VIEWS, _in_view

FORMAT = "REVENGINSTR.SemanticProgramGraphEvaluation/1"
GOLD_FORMAT = "REVENGINSTR.SemanticProgramGraphGold/1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_NODE_ID = re.compile(r"^(?:program|function|operation|field|receiver_observation|type|layout_field):[0-9a-f]{64}$")
_GOLD_SOURCE_OPCODES = {
    "calls": {"CALL"},
    "reads": {"LOAD"},
    "writes": {"STORE"},
    "observes_receiver": {"CALLIND"},
}


def _nonempty_string(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{where}: expected a non-empty string")
    return value


def _evidence_refs(value: Any, where: str, graph_sha256: str) -> None:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{where}: gold edge needs source evidence_refs")
    for index, ref in enumerate(value, 1):
        ref_where = f"{where}: evidence_ref {index}"
        if not isinstance(ref, dict) or set(ref) != {"artifact_sha256", "record_index", "source_format"}:
            raise ValueError(f"{ref_where}: invalid fields")
        if not isinstance(ref["artifact_sha256"], str) or not _SHA256.fullmatch(ref["artifact_sha256"]):
            raise ValueError(f"{ref_where}: invalid artifact_sha256")
        if ref["artifact_sha256"] == graph_sha256:
            raise ValueError(f"{ref_where}: gold cannot cite the graph being evaluated")
        if type(ref["record_index"]) is not int or ref["record_index"] < 1:
            raise ValueError(f"{ref_where}: invalid record_index")
        _nonempty_string(ref["source_format"], ref_where)
        if ref["source_format"] in {FORMAT_V1, FORMAT_V2, FORMAT_V3, FORMAT}:
            raise ValueError(f"{ref_where}: gold evidence cannot cite graph output")


def _validate_gold_row(
    row: Any,
    *,
    record_index: int,
    graph_sha256: str,
    graph_format: str | None,
) -> tuple[str, str, str, str, set[str], set[str], set[tuple[str, str, str]]]:
    where = f"gold record {record_index}"
    fields = {
        "format", "subgraph_id", "dataset_id", "split_id", "program_id", "graph_id",
        "scope_node_ids", "complete_relations", "edges", "adjudication_status",
    }
    if not isinstance(row, dict) or set(row) != fields or row.get("format") != GOLD_FORMAT:
        raise ValueError(f"{where}: unsupported format or fields")
    subgraph_id = _nonempty_string(row["subgraph_id"], where)
    dataset_id = _nonempty_string(row["dataset_id"], where)
    split_id = _nonempty_string(row["split_id"], where)
    program_id = _nonempty_string(row["program_id"], where)
    graph_id = _nonempty_string(row["graph_id"], where)
    if row["adjudication_status"] != "adjudicated":
        raise ValueError(f"{where}: gold subgraph is not adjudicated")
    scope_rows = row["scope_node_ids"]
    if not isinstance(scope_rows, list) or not scope_rows:
        raise ValueError(f"{where}: scope_node_ids must be a non-empty array")
    if any(not isinstance(node_id, str) or not _NODE_ID.fullmatch(node_id) for node_id in scope_rows):
        raise ValueError(f"{where}: invalid scope node id")
    if len(scope_rows) != len(set(scope_rows)):
        raise ValueError(f"{where}: duplicate scope node id")
    relation_rows = row["complete_relations"]
    if (
        not isinstance(relation_rows, list)
        or not relation_rows
        or any(not isinstance(relation, str) or relation not in RELATIONS for relation in relation_rows)
        or len(relation_rows) != len(set(relation_rows))
    ):
        raise ValueError(f"{where}: invalid complete_relations")

    scope = set(scope_rows)
    complete_relations = set(relation_rows)
    valid_endpoints = _valid_edge_endpoints(graph_format or FORMAT_V2)
    gold_edges: set[tuple[str, str, str]] = set()
    if not isinstance(row["edges"], list):
        raise ValueError(f"{where}: edges must be an array")
    for edge_index, edge in enumerate(row["edges"], 1):
        edge_where = f"{where}: edge {edge_index}"
        if not isinstance(edge, dict) or set(edge) != {"from", "to", "relation", "evidence_refs"}:
            raise ValueError(f"{edge_where}: invalid fields")
        source = edge["from"]
        target = edge["to"]
        relation = edge["relation"]
        if not isinstance(source, str) or source not in scope or not _NODE_ID.fullmatch(source):
            raise ValueError(f"{edge_where}: source is outside the audited scope")
        if not isinstance(target, str) or target not in scope or not _NODE_ID.fullmatch(target):
            raise ValueError(f"{edge_where}: target is outside the audited scope")
        if not isinstance(relation, str) or relation not in complete_relations:
            raise ValueError(f"{edge_where}: relation is not declared complete")
        endpoint_kinds = (source.split(":", 1)[0], target.split(":", 1)[0])
        if endpoint_kinds not in valid_endpoints.get(relation, set()):
            raise ValueError(f"{edge_where}: invalid endpoint kinds for relation {relation!r}")
        key = (relation, source, target)
        if key in gold_edges:
            raise ValueError(f"{edge_where}: duplicate gold edge")
        _evidence_refs(edge["evidence_refs"], edge_where, graph_sha256)
        gold_edges.add(key)
    return subgraph_id, dataset_id, split_id, graph_id, scope, complete_relations, gold_edges


def _provenance_complete(edge: dict[str, Any]) -> bool:
    supports = edge.get("support")
    if not isinstance(supports, list) or not supports:
        return False
    for support in supports:
        if (
            not isinstance(support, dict)
            or not isinstance(support.get("evidence_class"), str)
            or not support["evidence_class"]
        ):
            return False
        effect_id = support.get("effect_id")
        source_record_id = support.get("source_record_id")
        effect_id_valid = isinstance(effect_id, str) and _SHA256.fullmatch(effect_id)
        source_record_id_valid = isinstance(source_record_id, str) and bool(source_record_id)
        if ("effect_id" in support and not effect_id_valid) or (
            "source_record_id" in support and not source_record_id_valid
        ):
            return False
        if not (effect_id_valid or source_record_id_valid):
            return False
        provenance = support.get("provenance")
        if not isinstance(provenance, dict):
            return False
        if not isinstance(provenance.get("source_format"), str) or not provenance["source_format"]:
            return False
        if not isinstance(provenance.get("artifact_sha256"), str) or not _SHA256.fullmatch(provenance["artifact_sha256"]):
            return False
        if type(provenance.get("record_index")) is not int or provenance["record_index"] < 1:
            return False
    return True


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def evaluate_semantic_program_graph(
    graph_path: Path,
    gold_path: Path,
    *,
    view: str = "exact-only",
    minimum_confidence: float = 0.95,
) -> dict[str, Any]:
    """Score only graph relations explicitly complete in adjudicated gold subgraphs."""
    if view not in VIEWS:
        raise ValueError(f"unsupported query view: {view!r}")
    if not 0 <= minimum_confidence <= 1:
        raise ValueError("minimum_confidence must be between 0 and 1")
    graphs, graph_sha256 = _read_jsonl(graph_path)
    gold_rows, gold_sha256 = _read_jsonl(gold_path)
    graph_by_id = {}
    for index, graph in enumerate(graphs, 1):
        if not isinstance(graph, dict) or graph.get("format") not in {FORMAT_V1, FORMAT_V2, FORMAT_V3}:
            raise ValueError(f"graph record {index}: unsupported semantic graph")
        validate_graph_references(graph)
        if graph["graph_id"] in graph_by_id:
            raise ValueError(f"graph record {index}: duplicate graph id")
        graph_by_id[graph["graph_id"]] = graph

    metadata: tuple[str, str] | None = None
    seen_subgraphs: set[str] = set()
    seen_gold_edges: set[tuple[str, str, str, str]] = set()
    seen_evaluated_edges: set[tuple[str, str, str, str]] = set()
    per_relation: dict[str, dict[str, int]] = defaultdict(lambda: {
        "gold_edges": 0, "candidate_edges": 0, "true_positives": 0,
    })
    candidate_count = unsupported_count = accepted_count = accepted_true_positives = 0
    provenance_complete_count = 0

    for index, row in enumerate(gold_rows, 1):
        raw_graph_id = row.get("graph_id") if isinstance(row, dict) else None
        graph_hint = graph_by_id.get(raw_graph_id) if isinstance(raw_graph_id, str) else None
        parsed = _validate_gold_row(
            row,
            record_index=index,
            graph_sha256=graph_sha256,
            graph_format=graph_hint.get("format") if graph_hint else None,
        )
        subgraph_id, dataset_id, split_id, graph_id, scope, complete, gold_edges = parsed
        if subgraph_id in seen_subgraphs:
            raise ValueError(f"gold record {index}: duplicate subgraph_id")
        seen_subgraphs.add(subgraph_id)
        if metadata is None:
            metadata = (dataset_id, split_id)
        elif metadata != (dataset_id, split_id):
            raise ValueError(f"gold record {index}: mixed dataset or split identity")
        graph = graph_by_id.get(graph_id)
        if graph is None:
            raise ValueError(f"gold record {index}: graph_id is not present in graph input")
        if graph["program_id"] != row["program_id"]:
            raise ValueError(f"gold record {index}: program_id disagrees with graph")
        graph_nodes = {node["id"]: node for node in graph["nodes"]}
        for relation, source, _ in gold_edges:
            expected_opcodes = _GOLD_SOURCE_OPCODES.get(relation)
            source_node = graph_nodes.get(source)
            if (
                expected_opcodes is not None
                and source_node is not None
                and source_node.get("opcode") not in expected_opcodes
            ):
                raise ValueError(
                    f"gold record {index}: {relation!r} source operation has an incompatible opcode"
                )

        for relation, source, target in gold_edges:
            key = (graph_id, relation, source, target)
            if key in seen_gold_edges:
                raise ValueError(f"gold record {index}: overlapping subgraphs repeat a gold edge")
            seen_gold_edges.add(key)
        for relation in complete:
            per_relation[relation]["gold_edges"] += sum(edge[0] == relation for edge in gold_edges)
        scoped_edges = [
            edge for edge in graph["edges"]
            if edge["from"] in scope and edge["to"] in scope
        ]
        for edge in scoped_edges:
            if edge["relation"] not in complete:
                continue
            unique_key = (graph_id, edge["relation"], edge["from"], edge["to"])
            if unique_key in seen_evaluated_edges:
                raise ValueError(f"gold record {index}: overlapping subgraphs score the same edge twice")
            seen_evaluated_edges.add(unique_key)
        selected = [
            edge for edge in scoped_edges
            if edge["relation"] in complete and _in_view(edge, view, minimum_confidence)
        ]
        for edge in selected:
            key = (edge["relation"], edge["from"], edge["to"])
            candidate_count += 1
            per_relation[edge["relation"]]["candidate_edges"] += 1
            if key in gold_edges:
                per_relation[edge["relation"]]["true_positives"] += 1
            else:
                unsupported_count += 1
            provenance_complete_count += _provenance_complete(edge)
        accepted = [
            edge for edge in scoped_edges
            if edge["relation"] in complete
            and _in_view(edge, "accepted-high-confidence", minimum_confidence)
        ]
        accepted_count += len(accepted)
        accepted_true_positives += sum(
            (edge["relation"], edge["from"], edge["to"]) in gold_edges for edge in accepted
        )

    if metadata is None:
        raise ValueError("gold subgraph input is empty")
    relation_metrics = {}
    for relation, counts in sorted(per_relation.items()):
        relation_metrics[relation] = {
            **counts,
            "unsupported_edges": counts["candidate_edges"] - counts["true_positives"],
            "candidate_edge_precision": _ratio(counts["true_positives"], counts["candidate_edges"]),
            "recall": _ratio(counts["true_positives"], counts["gold_edges"]),
        }
    return {
        "format": FORMAT,
        "dataset_id": metadata[0],
        "split_id": metadata[1],
        "semantic_program_graph_sha256": graph_sha256,
        "gold_artifact_sha256": gold_sha256,
        "view": view,
        "minimum_confidence": minimum_confidence,
        "subgraphs_evaluated": len(seen_subgraphs),
        "candidate_edge_count": candidate_count,
        "unsupported_edge_count": unsupported_count,
        "unsupported_edge_rate": _ratio(unsupported_count, candidate_count),
        "accepted_edge_count": accepted_count,
        "accepted_edge_true_positives": accepted_true_positives,
        "accepted_edge_precision": _ratio(accepted_true_positives, accepted_count),
        "provenance_complete_edge_count": provenance_complete_count,
        "provenance_completeness": _ratio(provenance_complete_count, candidate_count),
        "per_relation": relation_metrics,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("semantic_program_graph", type=Path)
    parser.add_argument("gold_subgraphs", type=Path)
    parser.add_argument("--view", choices=VIEWS, default="exact-only")
    parser.add_argument("--minimum-confidence", type=float, default=0.95)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = evaluate_semantic_program_graph(
            args.semantic_program_graph,
            args.gold_subgraphs,
            view=args.view,
            minimum_confidence=args.minimum_confidence,
        )
    except ValueError as error:
        parser.error(str(error))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")
    print("subgraphs evaluated:", result["subgraphs_evaluated"])
    print("candidate edges:", result["candidate_edge_count"])
    print("unsupported edge rate:", result["unsupported_edge_rate"])
    print("accepted edge precision:", result["accepted_edge_precision"])
    print("evaluation:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
