"""Integrity checks for the project-neutral receiver provenance graph."""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

FORMAT = "REVENGINSTR.ReceiverProvenanceGraph/1"
RECEIVER_TYPE_FORMAT = "REVENGINSTR.GhidraIndirectReceiverType/1"
CALLER_ARGUMENT_FORMAT = "REVENGINSTR.GhidraCallerArgumentSubtree/1"
PARAMETER_STORE_FORMAT = "REVENGINSTR.GhidraParameterStoreField/1"
DEFAULT_MAX_ARGUMENT_GRAPHS = 10_000


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


def build_caller_argument_graphs(
    rows: list[dict[str, str]], *, max_graphs: int = DEFAULT_MAX_ARGUMENT_GRAPHS
) -> tuple[list[dict[str, Any]], int]:
    """Project bounded direct-call argument roots into one-hop formal-parameter edges."""
    if max_graphs < 1:
        raise ValueError("max_graphs must be positive")

    graphs: list[dict[str, Any]] = []
    seen_roots: set[tuple[str, str, int, str, str, int]] = set()
    skipped_rows = 0

    for line_no, row in enumerate(rows, 2):
        if row.get("format") != CALLER_ARGUMENT_FORMAT:
            raise ValueError(f"caller argument row {line_no}: unsupported format")
        row_type = row.get("row_type")
        if row_type == "summary":
            skipped_rows += 1
            continue
        if row_type != "node":
            raise ValueError(f"caller argument row {line_no}: invalid row_type")
        if row.get("edge_kind") != "root" or row.get("depth") != "0":
            skipped_rows += 1
            continue

        plan_id = row.get("plan_id", "")
        callee_entry = row.get("callee_entry", "")
        caller_entry = row.get("caller_entry", "")
        call_site = row.get("caller_call_site", "")
        parameter_text = row.get("parameter_index", "")
        node_text = row.get("node_id", "")
        if (
            not plan_id
            or not callee_entry
            or not caller_entry
            or caller_entry == "-"
            or not call_site
            or call_site == "-"
            or not parameter_text.isascii()
            or not parameter_text.isdecimal()
            or not node_text.isascii()
            or not node_text.isdecimal()
            or row.get("parent_node_id") != "-1"
        ):
            raise ValueError(f"caller argument row {line_no}: invalid root key")

        parameter_index = int(parameter_text)
        node_id = int(node_text)
        key = (plan_id, callee_entry, parameter_index, caller_entry, call_site, node_id)
        if key in seen_roots:
            raise ValueError(f"duplicate caller argument root: {key!r}")
        if len(graphs) >= max_graphs:
            raise ValueError(f"caller argument graph budget exceeded: {max_graphs}")
        seen_roots.add(key)

        graph_id = json.dumps(key, ensure_ascii=False, separators=(",", ":"))
        provenance = [{
            "source_format": CALLER_ARGUMENT_FORMAT,
            "source_id": graph_id,
        }]
        nodes = [
            {"id": "caller_argument", "kind": "call_argument"},
            {"id": "callee_parameter", "kind": "parameter"},
        ]
        edges = [{
            "id": "argument_flow",
            "from": "caller_argument",
            "to": "callee_parameter",
            "relation": "argument_flow",
            "evidence_class": "exact_static",
            "provenance": provenance,
        }]
        if row.get("defining_opcode") in {"CALL", "CALLIND"}:
            nodes.insert(1, {"id": "call_result", "kind": "return"})
            edges.append({
                "id": "call_return",
                "from": "call_result",
                "to": "caller_argument",
                "relation": "return_flow",
                "evidence_class": "exact_static",
                "provenance": provenance,
            })
        graph: dict[str, Any] = {
            "format": FORMAT,
            "graph_id": graph_id,
            "nodes": nodes,
            "edges": edges,
        }
        validate_graph_references(graph)
        graphs.append(graph)

    graphs.sort(key=lambda graph: graph["graph_id"])
    return graphs, skipped_rows


def caller_argument_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build bounded caller-argument provenance edges.")
    parser.add_argument("caller_argument_subtree_tsv", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-graphs", type=int, default=DEFAULT_MAX_ARGUMENT_GRAPHS)
    args = parser.parse_args(argv)

    from revenginstr.receiver.infer import read_tsv

    rows = read_tsv(args.caller_argument_subtree_tsv)
    graphs, skipped_rows = build_caller_argument_graphs(rows, max_graphs=args.max_graphs)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for graph in graphs:
            handle.write(json.dumps(graph, sort_keys=True) + "\n")
    print("input caller argument rows:", len(rows))
    print("root argument graphs:", len(graphs))
    print("subtree/summary rows skipped:", skipped_rows)
    print("max graphs:", args.max_graphs)
    print("output:", args.output)
    return 0


def _ascii_decimal(value: str) -> bool:
    return value.isascii() and value.isdecimal()


def build_parameter_store_graphs(
    rows: list[dict[str, str]],
    *,
    program_id: str,
    max_graphs: int = DEFAULT_MAX_ARGUMENT_GRAPHS,
) -> list[dict[str, Any]]:
    """Project parameter-to-parameter P-code stores into destination/value edges."""
    if not program_id:
        raise ValueError("program_id must be non-empty")
    if max_graphs < 1:
        raise ValueError("max_graphs must be positive")

    graphs: list[dict[str, Any]] = []
    seen_stores: set[tuple[Any, ...]] = set()

    for line_no, row in enumerate(rows, 2):
        if row.get("format") != PARAMETER_STORE_FORMAT:
            raise ValueError(f"parameter store row {line_no}: unsupported format")
        if row.get("status") != "parameter_to_parameter_field":
            raise ValueError(f"parameter store row {line_no}: unsupported status")

        function_entry = row.get("function_entry", "")
        store_address = row.get("store_address", "")
        store_time_text = row.get("store_time", "")
        destination_index_text = row.get("destination_parameter_index", "")
        source_index_text = row.get("source_parameter_index", "")
        offset_text = row.get("destination_offset", "")
        if (
            not function_entry
            or function_entry == "-"
            or not store_address
            or store_address == "-"
            or (store_time_text != "-" and not _ascii_decimal(store_time_text))
            or not _ascii_decimal(destination_index_text)
            or not _ascii_decimal(source_index_text)
            or re.fullmatch(r"-?0x[0-9a-f]+", offset_text) is None
        ):
            raise ValueError(f"parameter store row {line_no}: invalid store key")

        store_time = None if store_time_text == "-" else int(store_time_text)
        destination_index = int(destination_index_text)
        source_index = int(source_index_text)
        offset = int(offset_text, 0)
        key = (
            program_id, function_entry, store_address, store_time,
            destination_index, offset, source_index,
        )
        if key in seen_stores:
            raise ValueError(f"duplicate parameter store: {key!r}")
        if len(graphs) >= max_graphs:
            raise ValueError(f"parameter store graph budget exceeded: {max_graphs}")
        seen_stores.add(key)

        graph_id = json.dumps(key, ensure_ascii=False, separators=(",", ":"))
        destination_node = f"parameter:{destination_index}"
        source_node = f"parameter:{source_index}"
        nodes = [
            {"id": destination_node, "kind": "parameter"},
            {"id": "store", "kind": "field_store"},
        ]
        if source_node != destination_node:
            nodes.insert(1, {"id": source_node, "kind": "parameter"})
        provenance = [{
            "source_format": PARAMETER_STORE_FORMAT,
            "source_id": graph_id,
        }]
        graph: dict[str, Any] = {
            "format": FORMAT,
            "graph_id": graph_id,
            "nodes": nodes,
            "edges": [
                {
                    "id": "destination_field",
                    "from": destination_node,
                    "to": "store",
                    "relation": "field_store",
                    "evidence_class": "exact_static",
                    "provenance": provenance,
                },
                {
                    "id": "stored_value",
                    "from": source_node,
                    "to": "store",
                    "relation": "data_flow",
                    "evidence_class": "exact_static",
                    "provenance": provenance,
                },
            ],
        }
        validate_graph_references(graph)
        graphs.append(graph)

    graphs.sort(key=lambda graph: graph["graph_id"])
    return graphs


def parameter_store_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build bounded parameter-to-field-store provenance graphs.")
    parser.add_argument("parameter_store_tsv", type=Path)
    parser.add_argument("--program-id", required=True, help="Opaque consumer join key for the selected program.")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-graphs", type=int, default=DEFAULT_MAX_ARGUMENT_GRAPHS)
    args = parser.parse_args(argv)

    from revenginstr.receiver.infer import read_tsv

    rows = read_tsv(args.parameter_store_tsv)
    graphs = build_parameter_store_graphs(
        rows, program_id=args.program_id, max_graphs=args.max_graphs
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for graph in graphs:
            handle.write(json.dumps(graph, sort_keys=True) + "\n")
    print("input parameter stores:", len(rows))
    print("store graphs:", len(graphs))
    print("max graphs:", args.max_graphs)
    print("output:", args.output)
    return 0


def build_argument_store_graphs(
    argument_rows: list[dict[str, str]],
    store_rows: list[dict[str, str]],
    *,
    program_id: str,
    max_graphs: int = DEFAULT_MAX_ARGUMENT_GRAPHS,
) -> list[dict[str, Any]]:
    """Join caller roots to callee stores only on exact function/parameter keys."""
    if not program_id:
        raise ValueError("program_id must be non-empty")
    if max_graphs < 1:
        raise ValueError("max_graphs must be positive")

    argument_graphs, _skipped = build_caller_argument_graphs(argument_rows, max_graphs=max_graphs)
    store_graphs = build_parameter_store_graphs(
        store_rows, program_id=program_id, max_graphs=max_graphs
    )
    roots_by_formal: dict[tuple[str, int], list[dict[str, Any]]] = {}
    # The existing builders serialize their validated join keys into graph ids.
    for graph in argument_graphs:
        identity = json.loads(graph["graph_id"])
        roots_by_formal.setdefault((identity[1], identity[2]), []).append(graph)

    joined_graphs: list[dict[str, Any]] = []
    for store_graph in store_graphs:
        identity = json.loads(store_graph["graph_id"])
        _program_id, function_entry, _address, _time, destination_index, _offset, source_index = identity
        for parameter_index in {destination_index, source_index}:
            for argument_graph in roots_by_formal.get((function_entry, parameter_index), []):
                if len(joined_graphs) >= max_graphs:
                    raise ValueError(f"argument-store graph budget exceeded: {max_graphs}")

                store_node_ids: dict[str, str] = {}
                store_nodes_by_id: dict[str, dict[str, str]] = {}
                for node in store_graph["nodes"]:
                    if node["kind"] == "field_store":
                        node_id = "field_store"
                    elif node["id"] == f"parameter:{parameter_index}":
                        node_id = "callee_parameter"
                    else:
                        node_id = f"store_{node['id']}"
                    store_node_ids[node["id"]] = node_id
                    store_nodes_by_id.setdefault(node_id, {"id": node_id, "kind": node["kind"]})

                edges = [dict(edge) for edge in argument_graph["edges"]]
                for edge in store_graph["edges"]:
                    edges.append({
                        **edge,
                        "id": f"store_{edge['id']}",
                        "from": store_node_ids[edge["from"]],
                        "to": store_node_ids[edge["to"]],
                    })
                argument_node_ids = {node["id"] for node in argument_graph["nodes"]}
                graph = {
                    "format": FORMAT,
                    "graph_id": json.dumps(
                        [program_id, argument_graph["graph_id"], store_graph["graph_id"]],
                        ensure_ascii=False, separators=(",", ":"),
                    ),
                    "nodes": [*argument_graph["nodes"], *(
                        node for node_id, node in store_nodes_by_id.items()
                        if node_id not in argument_node_ids
                    )],
                    "edges": edges,
                }
                validate_graph_references(graph)
                joined_graphs.append(graph)

    joined_graphs.sort(key=lambda graph: graph["graph_id"])
    return joined_graphs


def argument_store_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Join exact caller-argument roots to parameter field stores.")
    parser.add_argument("caller_argument_subtree_tsv", type=Path)
    parser.add_argument("parameter_store_tsv", type=Path)
    parser.add_argument("--program-id", required=True, help="Opaque consumer join key for the selected program.")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-graphs", type=int, default=DEFAULT_MAX_ARGUMENT_GRAPHS)
    args = parser.parse_args(argv)

    from revenginstr.receiver.infer import read_tsv

    argument_rows = read_tsv(args.caller_argument_subtree_tsv)
    store_rows = read_tsv(args.parameter_store_tsv)
    graphs = build_argument_store_graphs(
        argument_rows, store_rows, program_id=args.program_id, max_graphs=args.max_graphs
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for graph in graphs:
            handle.write(json.dumps(graph, sort_keys=True) + "\n")
    print("input caller argument rows:", len(argument_rows))
    print("input parameter stores:", len(store_rows))
    print("joined graphs:", len(graphs))
    print("max graphs:", args.max_graphs)
    print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
