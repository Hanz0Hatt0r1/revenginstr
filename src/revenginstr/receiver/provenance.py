"""Integrity checks for the project-neutral receiver provenance graph."""
from __future__ import annotations

from typing import Any

FORMAT = "REVENGINSTR.ReceiverProvenanceGraph/1"


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
