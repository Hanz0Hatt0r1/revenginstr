"""Build a deterministic program graph from versioned Function Effect IR."""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from revenginstr.structured_summary import validate_function_effect_ir

FORMAT = "REVENGINSTR.SemanticProgramGraph/1"
EFFECT_FORMATS = {
    "REVENGINSTR.FunctionEffectIR/1",
    "REVENGINSTR.FunctionEffectIR/2",
}


def _stable_id(kind: str, identity: list[Any]) -> str:
    encoded = json.dumps(identity, ensure_ascii=False, separators=(",", ":"))
    return f"{kind}:{hashlib.sha256(encoded.encode('utf-8')).hexdigest()}"


def _support(effect: dict[str, Any]) -> dict[str, Any]:
    return {
        "effect_id": effect["effect_id"],
        "evidence_class": effect["evidence_class"],
        "provenance": effect["provenance"],
    }


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
    known = {row["effect_id"] for row in current["support"]}
    current["support"].extend(row for row in node["support"] if row["effect_id"] not in known)
    current["support"].sort(key=lambda row: row["effect_id"])
    current["evidence_class"] = _evidence_class(current["support"])
    if node["conflict_state"] == "contested":
        current["conflict_state"] = "contested"


def _add_edge(edges: dict[str, dict[str, Any]], edge: dict[str, Any]) -> None:
    edge["id"] = _stable_id("edge", [edge["from"], edge["to"], edge["relation"]])
    current = edges.setdefault(edge["id"], {
        **edge, "support": [], "confidence": None, "conflict_state": "uncontested",
    })
    known = {row["effect_id"] for row in current["support"]}
    current["support"].extend(row for row in edge["support"] if row["effect_id"] not in known)
    current["support"].sort(key=lambda row: row["effect_id"])
    current["evidence_class"] = _evidence_class(current["support"])
    if edge["conflict_state"] == "contested":
        current["conflict_state"] = "contested"


def validate_graph_references(graph: dict[str, Any]) -> None:
    if graph.get("format") != FORMAT:
        raise ValueError(f"expected {FORMAT} record")
    node_ids = [node["id"] for node in graph["nodes"]]
    edge_ids = [edge["id"] for edge in graph["edges"]]
    if len(node_ids) != len(set(node_ids)):
        raise ValueError("duplicate semantic program graph node id")
    if len(edge_ids) != len(set(edge_ids)):
        raise ValueError("duplicate semantic program graph edge id")
    kinds = {node["id"]: node["kind"] for node in graph["nodes"]}
    for node in graph["nodes"]:
        if node["id"].split(":", 1)[0] != node["kind"]:
            raise ValueError(f"semantic program graph node {node['id']!r} has a mismatched kind")
    valid_endpoints = {
        "contains": {("program", "function"), ("function", "operation")},
        "calls": {("operation", "function")},
        "reads": {("operation", "field")},
        "writes": {("operation", "field")},
    }
    for edge in graph["edges"]:
        source_kind = kinds.get(edge["from"])
        target_kind = kinds.get(edge["to"])
        if source_kind is None or target_kind is None:
            raise ValueError(f"semantic program graph edge {edge['id']!r} has a dangling endpoint")
        if (source_kind, target_kind) not in valid_endpoints.get(edge["relation"], set()):
            raise ValueError(f"semantic program graph edge {edge['id']!r} has invalid endpoint kinds")
        if edge["id"] != _stable_id("edge", [edge["from"], edge["to"], edge["relation"]]):
            raise ValueError(f"semantic program graph edge {edge['id']!r} has an invalid id")


def build_semantic_program_graphs(
    records: list[dict[str, Any]], *, source_sha256: str
) -> list[dict[str, Any]]:
    """Project effect, call, and parameter-field facts without semantic guesses."""
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

    graphs: list[dict[str, Any]] = []
    for program_id, functions in sorted(by_program.items()):
        nodes: dict[str, dict[str, Any]] = {}
        edges: dict[str, dict[str, Any]] = {}
        all_support: list[dict[str, Any]] = []
        program_node = _stable_id("program", [program_id])

        for function in sorted(functions, key=lambda row: row["function_entry"]):
            entry = function["function_entry"]
            function_node = _stable_id("function", [program_id, entry])
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
            "format": FORMAT,
            "graph_id": _stable_id("program", [program_id]),
            "program_id": program_id,
            "source_effect_ir_format": effect_format,
            "source_effect_ir_sha256": source_sha256,
            "nodes": sorted(nodes.values(), key=lambda row: row["id"]),
            "edges": sorted(edges.values(), key=lambda row: row["id"]),
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
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    records, source_sha256 = _read_jsonl(args.function_effect_ir)
    graphs = build_semantic_program_graphs(records, source_sha256=source_sha256)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for graph in graphs:
            handle.write(json.dumps(graph, sort_keys=True) + "\n")
    print("program graphs:", len(graphs))
    print("nodes:", sum(len(graph["nodes"]) for graph in graphs))
    print("edges:", sum(len(graph["edges"]) for graph in graphs))
    print("source Effect IR SHA-256:", source_sha256)
    print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
