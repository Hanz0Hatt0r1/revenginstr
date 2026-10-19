"""Build a deterministic program graph from versioned Function Effect IR."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from revenginstr.structured_summary import validate_function_effect_ir

FORMAT_V1 = "REVENGINSTR.SemanticProgramGraph/1"
FORMAT_V2 = "REVENGINSTR.SemanticProgramGraph/2"
FORMAT = FORMAT_V1
RECEIVER_TYPE_FORMAT = "REVENGINSTR.GhidraIndirectReceiverType/1"
RECEIVER_COLUMNS = (
    "format", "source_id", "function_entry", "call_index", "call_address",
    "call_time", "arg_count", "receiver_present", "receiver_storage_kind",
    "receiver_token", "receiver_type_name", "receiver_type_display",
    "receiver_pointer_depth", "pointee_type_name", "pointee_type_display",
    "flow_type_node_count", "flow_single_pointer_pointee_names_json",
    "flow_single_pointer_pointee_displays_json",
)
EFFECT_FORMATS = {
    "REVENGINSTR.FunctionEffectIR/1",
    "REVENGINSTR.FunctionEffectIR/2",
}
_EDGE_ENDPOINTS = {
    "contains": {
        ("program", "function"),
        ("function", "operation"),
        ("function", "receiver_observation"),
    },
    "calls": {("operation", "function")},
    "reads": {("operation", "field")},
    "writes": {("operation", "field")},
    "observes_receiver": {("operation", "receiver_observation")},
}


def _valid_edge_endpoints(graph_format: str) -> dict[str, set[tuple[str, str]]]:
    endpoints = {relation: set(pairs) for relation, pairs in _EDGE_ENDPOINTS.items()}
    if graph_format == FORMAT_V1:
        endpoints["contains"].discard(("function", "receiver_observation"))
        endpoints.pop("observes_receiver")
    return endpoints


def _stable_id(kind: str, identity: list[Any]) -> str:
    encoded = json.dumps(identity, ensure_ascii=False, separators=(",", ":"))
    return f"{kind}:{hashlib.sha256(encoded.encode('utf-8')).hexdigest()}"


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _support(effect: dict[str, Any]) -> dict[str, Any]:
    return {
        "effect_id": effect["effect_id"],
        "evidence_class": effect["evidence_class"],
        "provenance": effect["provenance"],
    }


def _receiver_support(
    row: dict[str, Any], *, source_sha256: str, record_index: int
) -> dict[str, Any]:
    return {
        "source_record_id": f"{row['source_id']}#{row['call_index']}",
        "evidence_class": "observed_metadata",
        "provenance": {
            "source_format": RECEIVER_TYPE_FORMAT,
            "artifact_sha256": source_sha256,
            "record_index": record_index,
        },
    }


def _support_key(support: dict[str, Any]) -> tuple[Any, ...]:
    if "effect_id" in support:
        return ("effect", support["effect_id"])
    provenance = support["provenance"]
    return (
        "record", provenance["source_format"], provenance["artifact_sha256"],
        provenance["record_index"],
    )


def _evidence_class(support: list[dict[str, Any]]) -> str:
    classes = {row["evidence_class"] for row in support}
    return next(iter(classes)) if len(classes) == 1 else "mixed"


def _add_node(nodes: dict[str, dict[str, Any]], node: dict[str, Any]) -> None:
    current = nodes.setdefault(node["id"], {
        **node, "support": [], "confidence": None, "conflict_state": "uncontested",
    })
    identity_fields = {"support", "evidence_class", "confidence", "conflict_state"}
    if any(current[key] != node[key] for key in node if key not in identity_fields):
        raise ValueError(f"conflicting graph node identity: {node['id']}")
    known = {_support_key(row) for row in current["support"]}
    current["support"].extend(row for row in node["support"] if _support_key(row) not in known)
    current["support"].sort(key=_support_key)
    current["evidence_class"] = _evidence_class(current["support"])
    if node["conflict_state"] == "contested":
        current["conflict_state"] = "contested"


def _add_edge(edges: dict[str, dict[str, Any]], edge: dict[str, Any]) -> None:
    edge["id"] = _stable_id("edge", [edge["from"], edge["to"], edge["relation"]])
    current = edges.setdefault(edge["id"], {
        **edge, "support": [], "confidence": None, "conflict_state": "uncontested",
    })
    known = {_support_key(row) for row in current["support"]}
    current["support"].extend(row for row in edge["support"] if _support_key(row) not in known)
    current["support"].sort(key=_support_key)
    current["evidence_class"] = _evidence_class(current["support"])
    if edge["conflict_state"] == "contested":
        current["conflict_state"] = "contested"


def validate_graph_references(graph: dict[str, Any]) -> None:
    graph_format = graph.get("format")
    if graph_format not in {FORMAT_V1, FORMAT_V2}:
        raise ValueError(f"unsupported semantic program graph format: {graph_format!r}")
    node_ids = [node["id"] for node in graph["nodes"]]
    edge_ids = [edge["id"] for edge in graph["edges"]]
    if len(node_ids) != len(set(node_ids)):
        raise ValueError("duplicate semantic program graph node id")
    if len(edge_ids) != len(set(edge_ids)):
        raise ValueError("duplicate semantic program graph edge id")
    nodes = {node["id"]: node for node in graph["nodes"]}
    kinds = {node_id: node["kind"] for node_id, node in nodes.items()}
    for node in graph["nodes"]:
        if node["id"].split(":", 1)[0] != node["kind"]:
            raise ValueError(f"semantic program graph node {node['id']!r} has a mismatched kind")
    valid_endpoints = _valid_edge_endpoints(graph_format)
    observations_with_edges: set[str] = set()
    for edge in graph["edges"]:
        source_kind = kinds.get(edge["from"])
        target_kind = kinds.get(edge["to"])
        if source_kind is None or target_kind is None:
            raise ValueError(f"semantic program graph edge {edge['id']!r} has a dangling endpoint")
        if (source_kind, target_kind) not in valid_endpoints.get(edge["relation"], set()):
            raise ValueError(f"semantic program graph edge {edge['id']!r} has invalid endpoint kinds")
        if edge["id"] != _stable_id("edge", [edge["from"], edge["to"], edge["relation"]]):
            raise ValueError(f"semantic program graph edge {edge['id']!r} has an invalid id")
        if edge["relation"] == "observes_receiver":
            operation = nodes[edge["from"]]
            observation = nodes[edge["to"]]
            if (
                operation["opcode"] != "CALLIND"
                or operation["function_entry"] != observation["function_entry"]
                or operation["operation_address"] != observation["operation_address"]
                or operation["operation_time"] != observation["operation_time"]
            ):
                raise ValueError("receiver observation edge does not exactly match a CALLIND site")
            if observation["id"] in observations_with_edges:
                raise ValueError("receiver observation has multiple CALLIND joins")
            observations_with_edges.add(observation["id"])
    if graph_format == FORMAT_V2:
        for node in graph["nodes"]:
            if node["kind"] != "receiver_observation":
                continue
            has_edge = node["id"] in observations_with_edges
            expects_edge = node["join_state"] in {"matched", "matched_contested"}
            if has_edge != expects_edge:
                raise ValueError("receiver observation join_state disagrees with graph edges")


def _read_receiver_types(path: Path) -> tuple[list[dict[str, Any]], str]:
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"{path}: input must be UTF-8") from error
    reader = csv.DictReader(text.splitlines(), delimiter="\t")
    if tuple(reader.fieldnames or ()) != RECEIVER_COLUMNS:
        raise ValueError(f"{path}: unexpected {RECEIVER_TYPE_FORMAT} header")

    rows: list[dict[str, Any]] = []
    seen_calls: set[tuple[str, int]] = set()
    for record_index, row in enumerate(reader, 1):
        where = f"{path}:receiver record {record_index}"
        if None in row or any(not isinstance(value, str) for value in row.values()):
            raise ValueError(f"{where}: malformed TSV row")
        if row["format"] != RECEIVER_TYPE_FORMAT:
            raise ValueError(f"{where}: unsupported format")
        if not row["source_id"] or not row["function_entry"]:
            raise ValueError(f"{where}: missing source_id or function_entry")
        source_program, separator, source_entry = row["source_id"].rpartition(":")
        if not separator or not source_program or source_entry != row["function_entry"]:
            raise ValueError(f"{where}: source_id does not end in function_entry")
        for name in ("call_index", "call_time", "arg_count", "receiver_pointer_depth", "flow_type_node_count"):
            value = row[name]
            if not value.isascii() or not value.isdecimal():
                raise ValueError(f"{where}: invalid {name}")
        if row["receiver_present"] not in {"0", "1"}:
            raise ValueError(f"{where}: invalid receiver_present")
        key = (row["source_id"], int(row["call_index"]))
        if key in seen_calls:
            raise ValueError(f"{where}: duplicate receiver call {key[0]}#{key[1]}")
        seen_calls.add(key)
        parsed = dict(row)
        for name in ("call_index", "call_time", "arg_count", "receiver_pointer_depth", "flow_type_node_count"):
            parsed[name] = int(row[name])
        for source_name, target_name in (
            ("flow_single_pointer_pointee_names_json", "flow_single_pointer_pointee_names"),
            ("flow_single_pointer_pointee_displays_json", "flow_single_pointer_pointee_displays"),
        ):
            try:
                value = json.loads(row[source_name])
            except json.JSONDecodeError as error:
                raise ValueError(f"{where}: invalid {source_name}") from error
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                raise ValueError(f"{where}: {source_name} must be an array of strings")
            parsed[target_name] = value
        parsed["_record_index"] = record_index
        parsed["_source_program"] = source_program
        rows.append(parsed)
    return rows, hashlib.sha256(raw).hexdigest()


def build_semantic_program_graphs(
    records: list[dict[str, Any]], *, source_sha256: str,
    receiver_rows: list[dict[str, Any]] | None = None,
    receiver_sha256: str | None = None,
) -> list[dict[str, Any]]:
    """Project effects and optionally exact-call-site receiver observations."""
    if not records:
        raise ValueError("Function Effect IR input is empty")
    if any(not isinstance(record, dict) for record in records):
        raise ValueError("Function Effect IR records must be JSON objects")
    effect_format = records[0].get("format")
    if effect_format not in EFFECT_FORMATS:
        raise ValueError("unsupported Function Effect IR format")
    validate_function_effect_ir(records, source_sha256)

    by_program: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        by_program[record["program_id"]].append(record)
    receiver_by_program: dict[str, list[dict[str, Any]]] = defaultdict(list)
    if receiver_rows is not None:
        if receiver_sha256 is None or not _is_sha256(receiver_sha256):
            raise ValueError("receiver types require their source SHA-256")
        known_programs = set(by_program)
        for row in receiver_rows:
            program_id = row["_source_program"]
            if program_id not in known_programs:
                raise ValueError(f"receiver row belongs to unknown program: {program_id!r}")
            receiver_by_program[program_id].append(row)

    graphs: list[dict[str, Any]] = []
    for program_id, functions in sorted(by_program.items()):
        nodes: dict[str, dict[str, Any]] = {}
        edges: dict[str, dict[str, Any]] = {}
        all_support: list[dict[str, Any]] = []
        program_node = _stable_id("program", [program_id])
        function_nodes: dict[str, str] = {}
        effect_function_entries: set[str] = set()
        operations_by_site: dict[tuple[str, str, int | None], list[dict[str, Any]]] = defaultdict(list)

        for function in sorted(functions, key=lambda row: row["function_entry"]):
            entry = function["function_entry"]
            effect_function_entries.add(entry)
            function_node = _stable_id("function", [program_id, entry])
            function_nodes[entry] = function_node
            effects = function["effects"]
            supports = [_support(effect) for effect in effects]
            all_support.extend(supports)
            _add_node(nodes, {
                "id": function_node,
                "kind": "function",
                "entry": entry,
                "evidence_class": _evidence_class(supports),
                "support": supports,
                "confidence": None,
                "conflict_state": "uncontested",
            })

            operations: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
            for effect in effects:
                key = (
                    entry, effect["operation_address"], effect["operation_time"], effect["opcode"],
                )
                operations[key].append(effect)
            opcodes_by_site: dict[tuple[Any, ...], set[str]] = defaultdict(set)
            for function_entry, address, operation_time, opcode in operations:
                opcodes_by_site[(function_entry, address, operation_time)].add(opcode)

            for key, operation_effects in sorted(
                operations.items(),
                key=lambda item: (
                    item[0][0], item[0][1],
                    -1 if item[0][2] is None else item[0][2], item[0][3],
                ),
            ):
                _, address, operation_time, opcode = key
                opcode_conflict = len(opcodes_by_site[(entry, address, operation_time)]) > 1
                operation_node = _stable_id("operation", [program_id, *key])
                operation_support = [_support(effect) for effect in operation_effects]
                kinds = sorted({effect["kind"] for effect in operation_effects})
                targets: dict[str, list[dict[str, Any]]] = defaultdict(list)
                direct_calls = [effect for effect in operation_effects if effect["kind"] == "direct_call"]
                for effect in direct_calls:
                    target = effect["target_entry"]
                    if target not in (None, "-"):
                        targets[target].append(effect)
                if "indirect_call" in kinds:
                    target_state = "indirect"
                elif len(targets) > 1:
                    target_state = "conflicted"
                elif targets:
                    target_state = "resolved"
                elif "direct_call" in kinds:
                    target_state = "unresolved"
                else:
                    target_state = "not_applicable"
                conflict_reasons = []
                if len(targets) > 1:
                    conflict_reasons.append("target_disagreement")
                if opcode_conflict:
                    conflict_reasons.append("opcode_disagreement")
                _add_node(nodes, {
                    "id": operation_node,
                    "kind": "operation",
                    "function_entry": entry,
                    "operation_address": address,
                    "operation_time": operation_time,
                    "opcode": opcode,
                    "kinds": kinds,
                    "call_target_state": target_state,
                    "target_entries": sorted(targets),
                    "conflict_reasons": conflict_reasons,
                    "evidence_class": _evidence_class(operation_support),
                    "support": operation_support,
                    "confidence": None,
                    "conflict_state": "contested" if conflict_reasons else "uncontested",
                })
                operations_by_site[(entry, address, operation_time)].append(nodes[operation_node])
                _add_edge(edges, {
                    "from": function_node,
                    "to": operation_node,
                    "relation": "contains",
                    "evidence_class": _evidence_class(operation_support),
                    "support": operation_support,
                    "confidence": None,
                    "conflict_state": "uncontested",
                })

                for effect in operation_effects:
                    if effect["kind"] not in {"parameter_field_read", "parameter_field_write"}:
                        continue
                    field_identity = [program_id, entry, effect["parameter_index"], effect["field_offset"]]
                    field_node = _stable_id("field", field_identity)
                    support = [_support(effect)]
                    _add_node(nodes, {
                        "id": field_node,
                        "kind": "field",
                        "owner_function_entry": entry,
                        "parameter_index": effect["parameter_index"],
                        "field_offset": effect["field_offset"],
                        "evidence_class": "derived_structural",
                        "support": support,
                        "confidence": None,
                        "conflict_state": "uncontested",
                    })
                    relation = "reads" if effect["kind"] == "parameter_field_read" else "writes"
                    _add_edge(edges, {
                        "from": operation_node,
                        "to": field_node,
                        "relation": relation,
                        "evidence_class": "derived_structural",
                        "support": support,
                        "confidence": None,
                        "conflict_state": "contested" if opcode_conflict else "uncontested",
                    })

                for target, call_effects in sorted(targets.items()):
                    target_node = _stable_id("function", [program_id, target])
                    support = [_support(effect) for effect in call_effects]
                    conflict_state = "contested" if conflict_reasons else "uncontested"
                    _add_node(nodes, {
                        "id": target_node,
                        "kind": "function",
                        "entry": target,
                        "evidence_class": "exact_static",
                        "support": support,
                        "confidence": None,
                        "conflict_state": "uncontested",
                    })
                    _add_edge(edges, {
                        "from": operation_node,
                        "to": target_node,
                        "relation": "calls",
                        "evidence_class": "exact_static",
                        "support": support,
                        "confidence": None,
                        "conflict_state": conflict_state,
                    })

        for row in receiver_by_program.get(program_id, []):
            entry = row["function_entry"]
            function_node = function_nodes.get(entry)
            support = _receiver_support(
                row, source_sha256=receiver_sha256, record_index=row["_record_index"]
            )
            all_support.append(support)
            if function_node is None:
                function_node = _stable_id("function", [program_id, entry])
                function_nodes[entry] = function_node
                _add_node(nodes, {
                    "id": function_node,
                    "kind": "function",
                    "entry": entry,
                    "evidence_class": "observed_metadata",
                    "support": [support],
                    "confidence": None,
                    "conflict_state": "uncontested",
                })

            address = row["call_address"]
            operation_time = row["call_time"]
            same_site = operations_by_site.get((entry, address, operation_time), [])
            candidates = [operation for operation in same_site if operation["opcode"] == "CALLIND"]
            if len(candidates) == 1:
                operation = candidates[0]
                join_state = (
                    "matched_contested"
                    if operation["conflict_state"] == "contested"
                    else "matched"
                )
                conflict_reasons = operation.get("conflict_reasons", [])
            elif candidates:
                operation = None
                join_state = "ambiguous"
                conflict_reasons = []
            elif same_site:
                operation = None
                join_state = "call_site_not_indirect"
                conflict_reasons = []
            elif entry not in effect_function_entries:
                operation = None
                join_state = "function_not_in_effect_ir"
                conflict_reasons = []
            else:
                operation = None
                join_state = "call_site_not_found"
                conflict_reasons = []

            observation_node = _stable_id("receiver_observation", [
                program_id, row["source_id"], row["call_index"],
            ])
            _add_node(nodes, {
                "id": observation_node,
                "kind": "receiver_observation",
                "function_entry": entry,
                "call_index": row["call_index"],
                "operation_address": address,
                "operation_time": operation_time,
                "join_state": join_state,
                "receiver_present": row["receiver_present"] == "1",
                "receiver_storage_kind": row["receiver_storage_kind"],
                "receiver_token": row["receiver_token"],
                "receiver_type_name": row["receiver_type_name"],
                "receiver_type_display": row["receiver_type_display"],
                "receiver_pointer_depth": row["receiver_pointer_depth"],
                "pointee_type_name": row["pointee_type_name"],
                "pointee_type_display": row["pointee_type_display"],
                "flow_type_node_count": row["flow_type_node_count"],
                "flow_single_pointer_pointee_names": row["flow_single_pointer_pointee_names"],
                "flow_single_pointer_pointee_displays": row["flow_single_pointer_pointee_displays"],
                "evidence_class": "observed_metadata",
                "support": [support],
                "confidence": None,
                "conflict_state": "contested" if join_state == "matched_contested" else "uncontested",
                "conflict_reasons": conflict_reasons,
            })
            _add_edge(edges, {
                "from": function_node,
                "to": observation_node,
                "relation": "contains",
                "evidence_class": "observed_metadata",
                "support": [support],
                "confidence": None,
                "conflict_state": "uncontested",
            })
            if operation is not None:
                _add_edge(edges, {
                    "from": operation["id"],
                    "to": observation_node,
                    "relation": "observes_receiver",
                    "evidence_class": "observed_metadata",
                    "support": [support],
                    "confidence": None,
                    "conflict_state": "contested" if join_state == "matched_contested" else "uncontested",
                    "conflict_reasons": conflict_reasons,
                })

        _add_node(nodes, {
            "id": program_node,
            "kind": "program",
            "evidence_class": _evidence_class(all_support),
            "support": all_support,
            "confidence": None,
            "conflict_state": "uncontested",
        })
        for node in list(nodes.values()):
            if node["kind"] == "function":
                _add_edge(edges, {
                    "from": program_node,
                    "to": node["id"],
                    "relation": "contains",
                    "evidence_class": node["evidence_class"],
                    "support": node["support"],
                    "confidence": None,
                    "conflict_state": "uncontested",
                })

        graph = {
            "format": FORMAT_V2 if receiver_rows is not None else FORMAT_V1,
            "graph_id": _stable_id("program", [program_id]),
            "program_id": program_id,
            "source_effect_ir_format": effect_format,
            "source_effect_ir_sha256": source_sha256,
            "nodes": sorted(nodes.values(), key=lambda row: row["id"]),
            "edges": sorted(edges.values(), key=lambda row: row["id"]),
        }
        if receiver_rows is not None:
            graph["source_receiver_types_format"] = RECEIVER_TYPE_FORMAT
            graph["source_receiver_types_sha256"] = receiver_sha256
        graph = {
            key: graph[key]
            for key in (
                "format", "graph_id", "program_id", "source_effect_ir_format",
                "source_effect_ir_sha256", "source_receiver_types_format",
                "source_receiver_types_sha256", "nodes", "edges",
            )
            if key in graph
        }
        validate_graph_references(graph)
        graphs.append(graph)
    return graphs


def _read_jsonl(path: Path) -> tuple[list[dict[str, Any]], str]:
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"{path}: input must be UTF-8") from error
    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    records = []

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON object key {key!r}")
            result[key] = value
        return result

    for line_no, line in enumerate(lines, 1):
        if line.endswith("\r"):
            line = line[:-1]
        if not line.strip():
            raise ValueError(f"{path}: blank JSONL record at line {line_no}")
        try:
            record = json.loads(line, object_pairs_hook=unique_object)
        except json.JSONDecodeError as error:
            raise ValueError(f"{path}: invalid JSON at line {line_no}: {error.msg}") from error
        except ValueError as error:
            raise ValueError(f"{path}: invalid JSON at line {line_no}: {error}") from error
        if not isinstance(record, dict):
            raise ValueError(f"{path}: JSONL record {line_no} must be an object")
        records.append(record)
    return records, hashlib.sha256(raw).hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("function_effect_ir", type=Path)
    parser.add_argument(
        "--receiver-types", type=Path,
        help="optional GhidraIndirectReceiverType/1 TSV; joins only exact CALLIND function/address/time",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    records, source_sha256 = _read_jsonl(args.function_effect_ir)
    receiver_rows = None
    receiver_sha256 = None
    if args.receiver_types is not None:
        receiver_rows, receiver_sha256 = _read_receiver_types(args.receiver_types)
    graphs = build_semantic_program_graphs(
        records,
        source_sha256=source_sha256,
        receiver_rows=receiver_rows,
        receiver_sha256=receiver_sha256,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for graph in graphs:
            handle.write(json.dumps(graph, sort_keys=True) + "\n")
    print("program graphs:", len(graphs))
    print("nodes:", sum(len(graph["nodes"]) for graph in graphs))
    print("edges:", sum(len(graph["edges"]) for graph in graphs))
    print("source Effect IR SHA-256:", source_sha256)
    if receiver_sha256 is not None:
        print("source receiver types SHA-256:", receiver_sha256)
        print("receiver observations:", sum(
            node["kind"] == "receiver_observation"
            for graph in graphs for node in graph["nodes"]
        ))
    print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
