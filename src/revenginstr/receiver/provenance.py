"""Integrity checks for the project-neutral receiver provenance graph."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

FORMAT = "REVENGINSTR.ReceiverProvenanceGraph/1"
RECEIVER_TYPE_FORMAT = "REVENGINSTR.GhidraIndirectReceiverType/1"


def validate_graph_references(graph: dict[str, Any]) -> None:
    """Raise ``ValueError`` for duplicate graph ids or dangling edge endpoints.

    Validate the record's field types and enums with the published JSON Schema;
    this helper checks the references that JSON Schema cannot express.
    """
    if graph.get("format") != FORMAT:
        raise ValueError(f"expected {FORMAT} record")

    node_ids = [node["id"] for node in graph["nodes"]]
    if len(node_ids) != len(set(node_ids)):
        raise ValueError("duplicate receiver provenance node id")

    edge_ids = [edge["id"] for edge in graph["edges"]]
    if len(edge_ids) != len(set(edge_ids)):
        raise ValueError("duplicate receiver provenance edge id")

    known_nodes = set(node_ids)
    for edge in graph["edges"]:
        if edge["from"] not in known_nodes or edge["to"] not in known_nodes:
            raise ValueError(f"receiver provenance edge {edge['id']!r} has a dangling endpoint")


def build_receiver_graphs(
    receiver_rows: list[dict[str, str]],
) -> tuple[list[dict[str, Any]], int]:
    """Project typed receiver rows into one call-anchor graph per observed receiver.

    Rows without a receiver operand are counted and omitted. The graph records
    only the exact receiver-to-call relationship; type/class facts remain in the
    source row and are reachable through the edge's provenance reference.
    """
    graphs: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, int]] = set()
    calls_without_receiver = 0

    for line_no, row in enumerate(receiver_rows, 2):
        if row.get("format") != RECEIVER_TYPE_FORMAT:
            raise ValueError(f"receiver row {line_no}: unsupported format")
        source_id = row.get("source_id", "")
        call_index_text = row.get("call_index", "")
        if (
            not source_id
            or not call_index_text.isascii()
            or not call_index_text.isdecimal()
        ):
            raise ValueError(f"receiver row {line_no}: invalid receiver key")
        call_index = int(call_index_text)
        key = (source_id, call_index)
        if key in seen_keys:
            raise ValueError(f"duplicate receiver row: {source_id}#{call_index}")
        seen_keys.add(key)

        receiver_present = row.get("receiver_present")
        if receiver_present not in {"0", "1"}:
            raise ValueError(f"receiver row {line_no}: invalid receiver_present")
        if receiver_present == "0":
            calls_without_receiver += 1
            continue

        record_id = f"{source_id}#{call_index}"
        graph: dict[str, Any] = {
            "format": FORMAT,
            "graph_id": record_id,
            "nodes": [
                {"id": "receiver", "kind": "receiver"},
                {"id": "call", "kind": "indirect_call"},
            ],
            "edges": [{
                "id": "receiver_at_call",
                "from": "receiver",
                "to": "call",
                "relation": "receiver_at_call",
                "evidence_class": "exact_static",
                "provenance": [{
                    "source_format": RECEIVER_TYPE_FORMAT,
                    "source_id": record_id,
                }],
            }],
        }
        validate_graph_references(graph)
        graphs.append(graph)

    graphs.sort(key=lambda graph: graph["graph_id"])
    return graphs, calls_without_receiver


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receiver_types_tsv", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    from revenginstr.receiver.infer import read_tsv

    receiver_rows = read_tsv(args.receiver_types_tsv)
    graphs, calls_without_receiver = build_receiver_graphs(receiver_rows)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for graph in graphs:
            handle.write(json.dumps(graph, sort_keys=True) + "\n")
    print("input receiver rows:", len(receiver_rows))
    print("graphs emitted:", len(graphs))
    print("calls without receiver:", calls_without_receiver)
    print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
