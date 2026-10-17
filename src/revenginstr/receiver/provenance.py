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
PARAMETER_LOAD_FORMAT = "REVENGINSTR.GhidraParameterLoadField/1"
CALLER_PARAMETER_ROOT_FORMAT = "REVENGINSTR.GhidraCallerArgumentParameterRoot/1"
DEFAULT_MAX_ARGUMENT_GRAPHS = 10_000
DEFAULT_MAX_PROPAGATION_DEPTH = 8


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


def _parameter_load_identity(
    row: dict[str, str], *, program_id: str, line_no: int
) -> tuple[tuple[Any, ...], tuple[str, int]]:
    if row.get("format") != PARAMETER_LOAD_FORMAT:
        raise ValueError(f"parameter load row {line_no}: unsupported format")
    if row.get("status") != "parameter_field_load":
        raise ValueError(f"parameter load row {line_no}: unsupported status")

    function_entry = row.get("function_entry", "")
    load_address = row.get("load_address", "")
    load_time_text = row.get("load_time", "")
    parameter_text = row.get("base_parameter_index", "")
    offset_text = row.get("field_offset", "")
    value_token = row.get("value_token", "")
    if (
        not function_entry or function_entry == "-"
        or not load_address or load_address == "-"
        or (load_time_text != "-" and not _ascii_decimal(load_time_text))
        or not _ascii_decimal(parameter_text)
        or re.fullmatch(r"-?0x[0-9a-f]+", offset_text) is None
        or not value_token
    ):
        raise ValueError(f"parameter load row {line_no}: invalid load key")

    load_time = None if load_time_text == "-" else int(load_time_text)
    parameter_index = int(parameter_text)
    identity = (
        program_id, function_entry, load_address, load_time,
        parameter_index, int(offset_text, 0), value_token,
    )
    return identity, (function_entry, parameter_index)


def build_argument_load_graphs(
    argument_rows: list[dict[str, str]],
    load_rows: list[dict[str, str]],
    *,
    program_id: str,
    max_graphs: int = DEFAULT_MAX_ARGUMENT_GRAPHS,
) -> list[dict[str, Any]]:
    """Join caller roots to parameter-rooted loads by exact function/parameter keys."""
    if not program_id:
        raise ValueError("program_id must be non-empty")
    if max_graphs < 1:
        raise ValueError("max_graphs must be positive")

    argument_graphs, _skipped = build_caller_argument_graphs(argument_rows, max_graphs=max_graphs)
    roots_by_formal: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for graph in argument_graphs:
        identity = json.loads(graph["graph_id"])
        roots_by_formal.setdefault((identity[1], identity[2]), []).append(graph)

    seen_loads: set[tuple[Any, ...]] = set()
    joined_graphs: list[dict[str, Any]] = []
    for line_no, row in enumerate(load_rows, 2):
        load_key, join_key = _parameter_load_identity(row, program_id=program_id, line_no=line_no)
        if load_key in seen_loads:
            raise ValueError(f"duplicate parameter load: {load_key!r}")
        if len(seen_loads) >= max_graphs:
            raise ValueError(f"parameter load graph budget exceeded: {max_graphs}")
        seen_loads.add(load_key)

        source_id = json.dumps(load_key, ensure_ascii=False, separators=(",", ":"))
        for argument_graph in roots_by_formal.get(join_key, []):
            if len(joined_graphs) >= max_graphs:
                raise ValueError(f"argument-load graph budget exceeded: {max_graphs}")
            edges = [dict(edge) for edge in argument_graph["edges"]]
            edges.append({
                "id": "parameter_field_load",
                "from": "callee_parameter",
                "to": "field_load",
                "relation": "field_load",
                "evidence_class": "exact_static",
                "provenance": [{
                    "source_format": PARAMETER_LOAD_FORMAT,
                    "source_id": source_id,
                }],
            })
            graph = {
                "format": FORMAT,
                "graph_id": json.dumps(
                    [program_id, argument_graph["graph_id"], source_id],
                    ensure_ascii=False, separators=(",", ":"),
                ),
                "nodes": [
                    *argument_graph["nodes"],
                    {"id": "field_load", "kind": "field_load"},
                ],
                "edges": edges,
            }
            validate_graph_references(graph)
            joined_graphs.append(graph)

    joined_graphs.sort(key=lambda graph: graph["graph_id"])
    return joined_graphs


def argument_load_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Join exact caller-argument roots to parameter field loads.")
    parser.add_argument("caller_argument_subtree_tsv", type=Path)
    parser.add_argument("parameter_load_tsv", type=Path)
    parser.add_argument("--program-id", required=True, help="Opaque consumer join key for the selected program.")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-graphs", type=int, default=DEFAULT_MAX_ARGUMENT_GRAPHS)
    args = parser.parse_args(argv)

    from revenginstr.receiver.infer import read_tsv

    argument_rows = read_tsv(args.caller_argument_subtree_tsv)
    load_rows = read_tsv(args.parameter_load_tsv)
    graphs = build_argument_load_graphs(
        argument_rows, load_rows, program_id=args.program_id, max_graphs=args.max_graphs
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for graph in graphs:
            handle.write(json.dumps(graph, sort_keys=True) + "\n")
    print("input caller argument rows:", len(argument_rows))
    print("input parameter loads:", len(load_rows))
    print("joined graphs:", len(graphs))
    print("max graphs:", args.max_graphs)
    print("output:", args.output)
    return 0


def build_field_access_pair_graphs(
    store_rows: list[dict[str, str]],
    load_rows: list[dict[str, str]],
    *,
    program_id: str,
    max_graphs: int = DEFAULT_MAX_ARGUMENT_GRAPHS,
) -> list[dict[str, Any]]:
    """Pair same-function field accesses rooted at one parameter and offset."""
    if not program_id:
        raise ValueError("program_id must be non-empty")
    if max_graphs < 1:
        raise ValueError("max_graphs must be positive")

    store_graphs = build_parameter_store_graphs(
        store_rows, program_id=program_id, max_graphs=max_graphs
    )
    loads_by_access: dict[tuple[str, int, int], list[str]] = {}
    seen_loads: set[tuple[Any, ...]] = set()
    for line_no, row in enumerate(load_rows, 2):
        load_key, _join_key = _parameter_load_identity(row, program_id=program_id, line_no=line_no)
        if load_key in seen_loads:
            raise ValueError(f"duplicate parameter load: {load_key!r}")
        if len(seen_loads) >= max_graphs:
            raise ValueError(f"parameter load graph budget exceeded: {max_graphs}")
        seen_loads.add(load_key)
        _program_id, function_entry, _address, _time, parameter_index, offset, _value = load_key
        source_id = json.dumps(load_key, ensure_ascii=False, separators=(",", ":"))
        loads_by_access.setdefault((function_entry, parameter_index, offset), []).append(source_id)

    joined_graphs: list[dict[str, Any]] = []
    for store_graph in store_graphs:
        store_key = json.loads(store_graph["graph_id"])
        _program_id, function_entry, _address, _time, parameter_index, offset, _source = store_key
        access_key = (function_entry, parameter_index, offset)
        for load_source_id in loads_by_access.get(access_key, []):
            if len(joined_graphs) >= max_graphs:
                raise ValueError(f"field access pair graph budget exceeded: {max_graphs}")
            edges = [dict(edge) for edge in store_graph["edges"]]
            edges.append({
                "id": "compatible_field_load",
                "from": f"parameter:{parameter_index}",
                "to": "field_load",
                "relation": "field_load",
                "evidence_class": "exact_static",
                "provenance": [{
                    "source_format": PARAMETER_LOAD_FORMAT,
                    "source_id": load_source_id,
                }],
            })
            graph = {
                "format": FORMAT,
                "graph_id": json.dumps(
                    [program_id, store_graph["graph_id"], load_source_id],
                    ensure_ascii=False, separators=(",", ":"),
                ),
                "nodes": [
                    *store_graph["nodes"],
                    {"id": "field_load", "kind": "field_load"},
                ],
                "edges": edges,
            }
            validate_graph_references(graph)
            joined_graphs.append(graph)

    joined_graphs.sort(key=lambda graph: graph["graph_id"])
    return joined_graphs


def field_access_pairs_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Pair same-function parameter field accesses by exact base and offset."
    )
    parser.add_argument("parameter_store_tsv", type=Path)
    parser.add_argument("parameter_load_tsv", type=Path)
    parser.add_argument("--program-id", required=True, help="Opaque consumer join key for the selected program.")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-graphs", type=int, default=DEFAULT_MAX_ARGUMENT_GRAPHS)
    args = parser.parse_args(argv)

    from revenginstr.receiver.infer import read_tsv

    store_rows = read_tsv(args.parameter_store_tsv)
    load_rows = read_tsv(args.parameter_load_tsv)
    graphs = build_field_access_pair_graphs(
        store_rows, load_rows, program_id=args.program_id, max_graphs=args.max_graphs
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for graph in graphs:
            handle.write(json.dumps(graph, sort_keys=True) + "\n")
    print("input parameter stores:", len(store_rows))
    print("input parameter loads:", len(load_rows))
    print("compatible field access pairs:", len(graphs))
    print("max graphs:", args.max_graphs)
    print("output:", args.output)
    return 0


def _index_pcode_flow(
    pcode_rows: list[dict[str, str]],
) -> tuple[
    dict[tuple[str, str], dict[str, str]],
    dict[tuple[str, str], list[tuple[dict[str, str], int]]],
]:
    definitions: dict[tuple[str, str], dict[str, str]] = {}
    users: dict[tuple[str, str], list[tuple[dict[str, str], int]]] = {}
    seen_operations: set[tuple[str, str, int]] = set()
    for line_no, row in enumerate(pcode_rows, 2):
        function_entry = row.get("function_entry", "")
        op_address = row.get("op_address", "")
        op_time_text = row.get("op_time", "")
        opcode = row.get("opcode", "")
        output = row.get("output", "")
        inputs_text = row.get("inputs", "")
        if (
            not function_entry or function_entry == "-"
            or not op_address or op_address == "-"
            or not _ascii_decimal(op_time_text)
            or not opcode or not output or not inputs_text
        ):
            raise ValueError(f"P-code flow row {line_no}: invalid operation key")
        operation_key = (function_entry, op_address, int(op_time_text))
        if operation_key in seen_operations:
            raise ValueError(f"duplicate P-code flow operation: {operation_key!r}")
        seen_operations.add(operation_key)
        if output != "-":
            definition_key = (function_entry, output)
            if definition_key in definitions:
                raise ValueError(f"duplicate P-code output definition: {definition_key!r}")
            definitions[definition_key] = row
        inputs = [] if inputs_text == "-" else inputs_text.split(";")
        if any(not value for value in inputs):
            raise ValueError(f"P-code flow row {line_no}: invalid input token list")
        for index, value in enumerate(inputs):
            users.setdefault((function_entry, value), []).append((row, index))
    return definitions, users


def build_parameter_load_return_graphs(
    load_rows: list[dict[str, str]],
    pcode_rows: list[dict[str, str]],
    *,
    program_id: str,
    max_graphs: int = DEFAULT_MAX_ARGUMENT_GRAPHS,
) -> list[dict[str, Any]]:
    """Trace parameter-rooted load values through P-code uses to RETURN ops."""
    if not program_id:
        raise ValueError("program_id must be non-empty")
    if max_graphs < 1:
        raise ValueError("max_graphs must be positive")

    definitions, users = _index_pcode_flow(pcode_rows)

    seen_loads: set[tuple[Any, ...]] = set()
    graphs: list[dict[str, Any]] = []
    for line_no, row in enumerate(load_rows, 2):
        load_key, _join_key = _parameter_load_identity(row, program_id=program_id, line_no=line_no)
        if load_key in seen_loads:
            raise ValueError(f"duplicate parameter load: {load_key!r}")
        if len(seen_loads) >= max_graphs:
            raise ValueError(f"parameter load graph budget exceeded: {max_graphs}")
        seen_loads.add(load_key)

        load_token = row["value_token"]
        token_match = re.fullmatch(r"def:([A-Z][A-Z0-9_]*)@(.+):([0-9]+):([0-9]+)", load_token)
        if token_match is None or token_match.group(1) != "LOAD":
            raise ValueError(f"parameter load row {line_no}: unsupported load value token")
        _mnemonic, token_address, token_time_text, token_size_text = token_match.groups()
        load_time = load_key[3]
        value_size_text = row.get("value_size", "")
        if (
            load_time is None
            or token_address != load_key[2]
            or int(token_time_text) != load_time
            or not _ascii_decimal(value_size_text)
            or int(token_size_text) != int(value_size_text)
        ):
            raise ValueError(f"parameter load row {line_no}: load token does not match row identity")

        function_entry = row["function_entry"]
        start_token = f"def:{token_address}:{token_time_text}:{token_size_text}"
        load_operation = definitions.get((function_entry, start_token))
        if (
            load_operation is None
            or load_operation.get("opcode") != "LOAD"
            or load_operation.get("op_address") != token_address
            or load_operation.get("op_time") != token_time_text
        ):
            raise ValueError(f"parameter load row {line_no}: no matching P-code LOAD definition")

        load_source_id = json.dumps(load_key, ensure_ascii=False, separators=(",", ":"))
        parents: dict[str, tuple[str, dict[str, str]] | None] = {start_token: None}
        pending = [start_token]
        return_paths: dict[tuple[str, str, int], list[dict[str, str]]] = {}

        def path_to(value: str) -> list[dict[str, str]]:
            path: list[dict[str, str]] = []
            while value != start_token:
                parent = parents[value]
                assert parent is not None
                value, operation = parent
                path.append(operation)
            path.reverse()
            return [load_operation, *path]

        cursor = 0
        while cursor < len(pending):
            value = pending[cursor]
            cursor += 1
            for user, input_index in users.get((function_entry, value), []):
                if user["opcode"] in {"CALL", "CALLIND", "CALLOTHER"}:
                    continue
                if user["opcode"] == "INDIRECT" and input_index != 0:
                    continue
                if user["opcode"] == "RETURN":
                    return_key = (function_entry, user["op_address"], int(user["op_time"]))
                    if return_key not in return_paths:
                        if len(graphs) + len(return_paths) >= max_graphs:
                            raise ValueError(f"load-return graph budget exceeded: {max_graphs}")
                        return_paths[return_key] = [*path_to(value), user]
                    continue
                output = user["output"]
                if output != "-" and output not in parents:
                    parents[output] = (value, user)
                    pending.append(output)

        for return_key, path in return_paths.items():
            if len(graphs) >= max_graphs:
                raise ValueError(f"load-return graph budget exceeded: {max_graphs}")
            return_source_id = json.dumps(
                [program_id, *return_key], ensure_ascii=False, separators=(",", ":")
            )
            provenance = [{
                "source_format": PARAMETER_LOAD_FORMAT,
                "source_id": load_source_id,
            }]
            for operation in path:
                operation_source_id = json.dumps(
                    [program_id, operation["function_entry"], operation["op_address"],
                     int(operation["op_time"]), operation["opcode"]],
                    ensure_ascii=False, separators=(",", ":"),
                )
                provenance.append({
                    "source_format": "REVENGINSTR.GhidraFunctionPcodeFlow/1",
                    "source_id": operation_source_id,
                })
            graph = {
                "format": FORMAT,
                "graph_id": json.dumps(
                    [program_id, load_source_id, return_source_id],
                    ensure_ascii=False, separators=(",", ":"),
                ),
                "nodes": [
                    {"id": "field_load", "kind": "field_load"},
                    {"id": "return", "kind": "return"},
                ],
                "edges": [{
                    "id": "load_return_flow",
                    "from": "field_load",
                    "to": "return",
                    "relation": "return_flow",
                    "evidence_class": "derived_structural",
                    "provenance": provenance,
                }],
            }
            validate_graph_references(graph)
            graphs.append(graph)

    graphs.sort(key=lambda graph: graph["graph_id"])
    return graphs


def parameter_load_return_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Trace parameter-rooted field loads to function returns through P-code uses."
    )
    parser.add_argument("parameter_load_tsv", type=Path)
    parser.add_argument("function_pcode_flow_tsv", type=Path)
    parser.add_argument("--program-id", required=True, help="Opaque consumer join key for the selected program.")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-graphs", type=int, default=DEFAULT_MAX_ARGUMENT_GRAPHS)
    args = parser.parse_args(argv)

    from revenginstr.receiver.infer import read_tsv

    load_rows = read_tsv(args.parameter_load_tsv)
    pcode_rows = read_tsv(args.function_pcode_flow_tsv)
    graphs = build_parameter_load_return_graphs(
        load_rows, pcode_rows, program_id=args.program_id, max_graphs=args.max_graphs
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for graph in graphs:
            handle.write(json.dumps(graph, sort_keys=True) + "\n")
    print("input parameter loads:", len(load_rows))
    print("input P-code flow rows:", len(pcode_rows))
    print("load-return graphs:", len(graphs))
    print("max graphs:", args.max_graphs)
    print("output:", args.output)
    return 0


def build_call_return_graphs(
    pcode_rows: list[dict[str, str]],
    *,
    program_id: str,
    max_graphs: int = DEFAULT_MAX_ARGUMENT_GRAPHS,
) -> list[dict[str, Any]]:
    """Trace call results through P-code data dependencies to function returns."""
    if not program_id:
        raise ValueError("program_id must be non-empty")
    if max_graphs < 1:
        raise ValueError("max_graphs must be positive")

    definitions, users = _index_pcode_flow(pcode_rows)

    graphs: list[dict[str, Any]] = []
    for (function_entry, call_token), call in definitions.items():
        if call["opcode"] not in {"CALL", "CALLIND"}:
            continue
        parents: dict[str, tuple[str, dict[str, str]] | None] = {call_token: None}
        pending = [call_token]
        return_paths: dict[tuple[str, str, int], list[dict[str, str]]] = {}

        def path_to(value: str) -> list[dict[str, str]]:
            path: list[dict[str, str]] = []
            while value != call_token:
                parent = parents[value]
                assert parent is not None
                value, operation = parent
                path.append(operation)
            path.reverse()
            return [call, *path]

        cursor = 0
        while cursor < len(pending):
            value = pending[cursor]
            cursor += 1
            for user, input_index in users.get((function_entry, value), []):
                if user["opcode"] in {"CALL", "CALLIND", "CALLOTHER"}:
                    continue
                if user["opcode"] == "INDIRECT" and input_index != 0:
                    continue
                if user["opcode"] == "RETURN":
                    return_key = (function_entry, user["op_address"], int(user["op_time"]))
                    if return_key not in return_paths:
                        if len(graphs) + len(return_paths) >= max_graphs:
                            raise ValueError(f"call-return graph budget exceeded: {max_graphs}")
                        return_paths[return_key] = [*path_to(value), user]
                    continue
                output = user["output"]
                if output != "-" and output not in parents:
                    parents[output] = (value, user)
                    pending.append(output)

        for return_key, path in return_paths.items():
            if len(graphs) >= max_graphs:
                raise ValueError(f"call-return graph budget exceeded: {max_graphs}")
            call_source_id = json.dumps(
                [program_id, function_entry, call["op_address"], int(call["op_time"])],
                ensure_ascii=False, separators=(",", ":"),
            )
            return_source_id = json.dumps(
                [program_id, *return_key], ensure_ascii=False, separators=(",", ":")
            )
            provenance = []
            for operation in path:
                operation_source_id = json.dumps(
                    [program_id, operation["function_entry"], operation["op_address"],
                     int(operation["op_time"]), operation["opcode"]],
                    ensure_ascii=False, separators=(",", ":"),
                )
                provenance.append({
                    "source_format": "REVENGINSTR.GhidraFunctionPcodeFlow/1",
                    "source_id": operation_source_id,
                })
            graph = {
                "format": FORMAT,
                "graph_id": json.dumps(
                    [program_id, call_source_id, return_source_id],
                    ensure_ascii=False, separators=(",", ":"),
                ),
                "nodes": [
                    {"id": "call_result", "kind": "return"},
                    {"id": "function_return", "kind": "return"},
                ],
                "edges": [{
                    "id": "call_return_flow",
                    "from": "call_result",
                    "to": "function_return",
                    "relation": "return_flow",
                    "evidence_class": "derived_structural",
                    "provenance": provenance,
                }],
            }
            validate_graph_references(graph)
            graphs.append(graph)

    graphs.sort(key=lambda graph: graph["graph_id"])
    return graphs


def call_return_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Trace call-result data dependencies to function returns without inferring factory semantics."
    )
    parser.add_argument("function_pcode_flow_tsv", type=Path)
    parser.add_argument("--program-id", required=True, help="Opaque consumer join key for the selected program.")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-graphs", type=int, default=DEFAULT_MAX_ARGUMENT_GRAPHS)
    args = parser.parse_args(argv)

    from revenginstr.receiver.infer import read_tsv

    pcode_rows = read_tsv(args.function_pcode_flow_tsv)
    graphs = build_call_return_graphs(
        pcode_rows, program_id=args.program_id, max_graphs=args.max_graphs
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for graph in graphs:
            handle.write(json.dumps(graph, sort_keys=True) + "\n")
    print("input P-code flow rows:", len(pcode_rows))
    print("call-return graphs:", len(graphs))
    print("max graphs:", args.max_graphs)
    print("output:", args.output)
    return 0


def build_recursive_argument_graph(
    argument_rows: list[dict[str, str]],
    parameter_root_rows: list[dict[str, str]],
    *,
    target_entry: str,
    target_parameter_index: int,
    program_id: str,
    max_depth: int = DEFAULT_MAX_PROPAGATION_DEPTH,
    max_edges: int = DEFAULT_MAX_ARGUMENT_GRAPHS,
) -> dict[str, Any] | None:
    """Walk exact caller-formal roots backwards from one target formal parameter."""
    if not program_id:
        raise ValueError("program_id must be non-empty")
    if not target_entry or target_entry == "-" or target_parameter_index < 0:
        raise ValueError("target parameter key is invalid")
    if max_depth < 1:
        raise ValueError("max_depth must be positive")
    if max_edges < 1:
        raise ValueError("max_edges must be positive")

    argument_graphs, _skipped = build_caller_argument_graphs(argument_rows)
    argument_roots: dict[tuple[str, str, int, str, str, int], dict[str, Any]] = {}
    for graph in argument_graphs:
        identity = json.loads(graph["graph_id"])
        argument_roots[tuple(identity)] = graph

    incoming: dict[tuple[str, int], list[dict[str, Any]]] = {}
    seen_roots: set[tuple[str, str, int, str, str, int]] = set()
    for line_no, row in enumerate(parameter_root_rows, 2):
        if row.get("format") != CALLER_PARAMETER_ROOT_FORMAT:
            raise ValueError(f"caller parameter root row {line_no}: unsupported format")
        if row.get("status") != "direct_parameter_root":
            raise ValueError(f"caller parameter root row {line_no}: unsupported status")

        plan_id = row.get("plan_id", "")
        callee_entry = row.get("callee_entry", "")
        callee_parameter_text = row.get("parameter_index", "")
        caller_entry = row.get("caller_entry", "")
        call_site = row.get("caller_call_site", "")
        caller_parameter_text = row.get("caller_parameter_index", "")
        node_text = row.get("argument_node_id", "")
        if (
            not plan_id
            or not callee_entry or callee_entry == "-"
            or not caller_entry or caller_entry == "-"
            or not call_site or call_site == "-"
            or not _ascii_decimal(callee_parameter_text)
            or not _ascii_decimal(caller_parameter_text)
            or not _ascii_decimal(node_text)
        ):
            raise ValueError(f"caller parameter root row {line_no}: invalid root key")

        root_key = (
            plan_id, callee_entry, int(callee_parameter_text), caller_entry,
            call_site, int(node_text),
        )
        if root_key in seen_roots:
            raise ValueError(f"duplicate caller parameter root: {root_key!r}")
        seen_roots.add(root_key)
        argument_graph = argument_roots.get(root_key)
        if argument_graph is None:
            raise ValueError(f"caller parameter root row {line_no}: no matching argument root")

        source_key = (caller_entry, int(caller_parameter_text))
        target_key = (callee_entry, int(callee_parameter_text))
        source_id = json.dumps(
            [program_id, *root_key, source_key[1]], ensure_ascii=False, separators=(",", ":")
        )
        edge_key = (source_key, target_key, argument_graph["graph_id"], source_id)
        incoming.setdefault(target_key, []).append({
            "key": edge_key,
            "source": source_key,
            "target": target_key,
            "argument_source_id": argument_graph["graph_id"],
            "parameter_source_id": source_id,
        })

    target = (target_entry, target_parameter_index)
    depths = {target: 0}
    pending = [target]
    selected: dict[tuple[Any, ...], dict[str, Any]] = {}
    cursor = 0
    while cursor < len(pending):
        callee = pending[cursor]
        cursor += 1
        next_depth = depths[callee] + 1
        for edge in incoming.get(callee, []):
            selected[edge["key"]] = edge
            if len(selected) > max_edges:
                raise ValueError(f"recursive argument edge budget exceeded: {max_edges}")
            caller = edge["source"]
            if caller in depths:
                continue
            if next_depth > max_depth:
                raise ValueError(f"recursive argument depth exceeded: {max_depth}")
            depths[caller] = next_depth
            pending.append(caller)

    if not selected:
        return None

    parameter_keys = sorted({target, *(edge["source"] for edge in selected.values())})
    node_ids = {key: f"parameter_{index}" for index, key in enumerate(parameter_keys)}
    edges = []
    for index, edge in enumerate(sorted(selected.values(), key=lambda item: item["key"])):
        edges.append({
            "id": f"argument_flow_{index}",
            "from": node_ids[edge["source"]],
            "to": node_ids[edge["target"]],
            "relation": "argument_flow",
            "evidence_class": "exact_static",
            "provenance": [
                {
                    "source_format": CALLER_ARGUMENT_FORMAT,
                    "source_id": edge["argument_source_id"],
                },
                {
                    "source_format": CALLER_PARAMETER_ROOT_FORMAT,
                    "source_id": edge["parameter_source_id"],
                },
            ],
        })
    graph = {
        "format": FORMAT,
        "graph_id": json.dumps(
            [program_id, target_entry, target_parameter_index,
             sorted(edge["parameter_source_id"] for edge in selected.values())],
            ensure_ascii=False, separators=(",", ":"),
        ),
        "nodes": [{"id": node_ids[key], "kind": "parameter"} for key in parameter_keys],
        "edges": edges,
    }
    validate_graph_references(graph)
    return graph


def recursive_argument_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Propagate exact caller-formal roots recursively to one selected parameter."
    )
    parser.add_argument("caller_argument_subtree_tsv", type=Path)
    parser.add_argument("caller_parameter_roots_tsv", type=Path)
    parser.add_argument("--target-entry", required=True)
    parser.add_argument("--target-parameter-index", type=int, required=True)
    parser.add_argument("--program-id", required=True, help="Opaque consumer join key for the selected program.")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-depth", type=int, default=DEFAULT_MAX_PROPAGATION_DEPTH)
    parser.add_argument("--max-edges", type=int, default=DEFAULT_MAX_ARGUMENT_GRAPHS)
    args = parser.parse_args(argv)

    from revenginstr.receiver.infer import read_tsv

    argument_rows = read_tsv(args.caller_argument_subtree_tsv)
    parameter_root_rows = read_tsv(args.caller_parameter_roots_tsv)
    graph = build_recursive_argument_graph(
        argument_rows,
        parameter_root_rows,
        target_entry=args.target_entry,
        target_parameter_index=args.target_parameter_index,
        program_id=args.program_id,
        max_depth=args.max_depth,
        max_edges=args.max_edges,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        if graph is not None:
            handle.write(json.dumps(graph, sort_keys=True) + "\n")
    print("input caller argument rows:", len(argument_rows))
    print("input caller parameter roots:", len(parameter_root_rows))
    print("propagation graphs:", 0 if graph is None else 1)
    print("max depth:", args.max_depth)
    print("max edges:", args.max_edges)
    print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
