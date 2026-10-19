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
FORMAT_V3 = "REVENGINSTR.SemanticProgramGraph/3"
FORMAT_V4 = "REVENGINSTR.SemanticProgramGraph/4"
FORMAT = FORMAT_V1
RECEIVER_TYPE_FORMAT = "REVENGINSTR.GhidraIndirectReceiverType/1"
TYPE_LAYOUT_FORMAT = "REVENGINSTR.TypeLayoutHypothesis/1"
CALL_ARGUMENT_FORMAT = "REVENGINSTR.DirectCallArgumentObservation/1"
CALL_ARGUMENT_DEFINITION_FORMAT = "REVENGINSTR.DirectCallArgumentDefinition/1"
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
        ("program", "type"),
        ("function", "operation"),
        ("function", "receiver_observation"),
    },
    "calls": {("operation", "function")},
    "reads": {("operation", "field")},
    "writes": {("operation", "field")},
    "observes_receiver": {("operation", "receiver_observation")},
    "has_field": {("type", "layout_field")},
}


def _valid_edge_endpoints(graph_format: str) -> dict[str, set[tuple[str, str]]]:
    endpoints = {relation: set(pairs) for relation, pairs in _EDGE_ENDPOINTS.items()}
    if graph_format == FORMAT_V1:
        endpoints["contains"].discard(("function", "receiver_observation"))
        endpoints.pop("observes_receiver")
    if graph_format not in {FORMAT_V3, FORMAT_V4}:
        endpoints.pop("has_field")
        endpoints["contains"].discard(("program", "type"))
        endpoints["contains"].discard(("type", "layout_field"))
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


def _layout_support(
    row: dict[str, Any], *, source_sha256: str, record_index: int
) -> dict[str, Any]:
    return {
        "source_record_id": f"{row['type_id']}#{record_index}",
        "evidence_class": "derived_structural",
        "provenance": {
            "source_format": TYPE_LAYOUT_FORMAT,
            "artifact_sha256": source_sha256,
            "record_index": record_index,
        },
    }


def _validate_type_layout_rows(
    rows: list[dict[str, Any]], *, known_programs: set[str],
) -> dict[str, list[dict[str, Any]]]:
    if not rows:
        raise ValueError("TypeLayoutHypothesis input is empty")
    by_program: dict[str, list[dict[str, Any]]] = defaultdict(list)
    seen_types: set[tuple[str, str]] = set()
    for record_index, row in enumerate(rows, 1):
        where = f"type-layout record {record_index}"
        if not isinstance(row, dict) or set(row) != {
            "format", "program_id", "program_sha256", "type_id", "architecture",
            "status", "object_size", "fields", "vtable_anchors", "relationships",
            "conflicts",
        }:
            raise ValueError(f"{where}: malformed TypeLayoutHypothesis/1 fields")
        if row.get("format") != TYPE_LAYOUT_FORMAT:
            raise ValueError(f"{where}: unsupported format")
        program_id, type_id = row.get("program_id"), row.get("type_id")
        if not isinstance(program_id, str) or program_id not in known_programs:
            raise ValueError(f"{where}: program_id is absent from Function Effect IR")
        if not isinstance(type_id, str) or not type_id:
            raise ValueError(f"{where}: type_id must be a non-empty string")
        if not _is_sha256(row.get("program_sha256", "")):
            raise ValueError(f"{where}: invalid program_sha256")
        if row.get("status") not in {"candidate", "review", "conflicted"}:
            raise ValueError(f"{where}: invalid status")
        if not isinstance(row.get("architecture"), dict) or not isinstance(row.get("object_size"), dict):
            raise ValueError(f"{where}: missing architecture or object_size")
        for collection in ("fields", "vtable_anchors", "relationships", "conflicts"):
            if not isinstance(row.get(collection), list):
                raise ValueError(f"{where}: {collection} must be an array")
        identity = (program_id, type_id)
        if identity in seen_types:
            raise ValueError(f"{where}: duplicate type hypothesis {type_id!r}")
        seen_types.add(identity)
        offsets: set[int] = set()
        for field_index, field in enumerate(row["fields"], 1):
            field_where = f"{where}: field {field_index}"
            if not isinstance(field, dict) or set(field) != {
                "offset_bytes", "status", "accesses", "type_candidates", "conflicts",
            }:
                raise ValueError(f"{field_where}: malformed layout field")
            offset = field.get("offset_bytes")
            if type(offset) is not int or offset < 0 or offset in offsets:
                raise ValueError(f"{field_where}: invalid or duplicate offset_bytes")
            offsets.add(offset)
            if field.get("status") not in {"candidate", "review", "conflicted"}:
                raise ValueError(f"{field_where}: invalid status")
            if not all(isinstance(field.get(name), list) for name in ("accesses", "type_candidates", "conflicts")):
                raise ValueError(f"{field_where}: malformed evidence collections")
        by_program[program_id].append({**row, "_record_index": record_index})
    return by_program


def _validate_call_argument_rows(
    rows: list[dict[str, Any]], *, known_programs: set[str],
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, str]]:
    if not rows:
        raise ValueError("DirectCallArgumentObservation input is empty")
    by_program: dict[str, list[dict[str, Any]]] = defaultdict(list)
    program_hashes: dict[str, str] = {}
    seen_sites: set[tuple[str, str, str, int]] = set()
    expected_fields = {
        "format", "program_id", "program_sha256", "caller_entry", "callee_entry",
        "call_address", "call_time", "argument_count", "arguments", "evidence_ref",
    }
    for record_index, row in enumerate(rows, 1):
        where = f"call-argument record {record_index}"
        if not isinstance(row, dict) or set(row) != expected_fields:
            raise ValueError(f"{where}: malformed DirectCallArgumentObservation/1 fields")
        if row.get("format") != CALL_ARGUMENT_FORMAT:
            raise ValueError(f"{where}: unsupported format")
        program_id = row.get("program_id")
        if not isinstance(program_id, str) or program_id not in known_programs:
            raise ValueError(f"{where}: program_id is absent from Function Effect IR")
        program_sha256 = row.get("program_sha256")
        if not isinstance(program_sha256, str) or not _is_sha256(program_sha256):
            raise ValueError(f"{where}: invalid program_sha256")
        if program_id in program_hashes and program_hashes[program_id] != program_sha256:
            raise ValueError(f"{where}: program_sha256 conflicts within program")
        program_hashes[program_id] = program_sha256
        for name in ("caller_entry", "callee_entry", "call_address"):
            if not isinstance(row.get(name), str) or not row[name]:
                raise ValueError(f"{where}: {name} must be a non-empty string")
        call_time = row.get("call_time")
        argument_count = row.get("argument_count")
        if type(call_time) is not int or call_time < 0:
            raise ValueError(f"{where}: call_time must be a non-negative integer")
        if type(argument_count) is not int or argument_count < 0:
            raise ValueError(f"{where}: argument_count must be a non-negative integer")
        arguments = row.get("arguments")
        if not isinstance(arguments, list) or len(arguments) != argument_count:
            raise ValueError(f"{where}: argument_count disagrees with arguments")
        for argument_index, argument in enumerate(arguments):
            if not isinstance(argument, dict) or set(argument) != {"index", "value_token", "width_bytes"}:
                raise ValueError(f"{where}: malformed argument {argument_index}")
            if type(argument.get("index")) is not int or argument["index"] != argument_index:
                raise ValueError(f"{where}: argument indices must be contiguous from zero")
            if not isinstance(argument.get("value_token"), str) or not argument["value_token"]:
                raise ValueError(f"{where}: argument value_token must be non-empty")
            if type(argument.get("width_bytes")) is not int or argument["width_bytes"] < 1:
                raise ValueError(f"{where}: argument width_bytes must be positive")
        evidence_ref = row.get("evidence_ref")
        if not isinstance(evidence_ref, dict) or set(evidence_ref) != {
            "artifact_sha256", "record_index", "source_format",
        }:
            raise ValueError(f"{where}: malformed evidence_ref")
        if (
            not _is_sha256(evidence_ref.get("artifact_sha256", ""))
            or type(evidence_ref.get("record_index")) is not int
            or evidence_ref["record_index"] < 1
            or evidence_ref.get("source_format") != "REVENGINSTR.GhidraFunctionPcodeFlow/1"
        ):
            raise ValueError(f"{where}: invalid P-code evidence_ref")
        site = (program_id, row["caller_entry"], row["call_address"], call_time)
        if site in seen_sites:
            raise ValueError(f"{where}: duplicate call site {site[1:]}")
        seen_sites.add(site)
        by_program[program_id].append({**row, "_record_index": record_index})
    return by_program, program_hashes


def _validate_call_argument_definition_rows(
    rows: list[dict[str, Any]], *,
    call_arguments_by_program: dict[str, list[dict[str, Any]]],
    call_argument_sha256: str,
) -> dict[str, dict[tuple[int, int], dict[str, Any]]]:
    if not rows:
        raise ValueError("DirectCallArgumentDefinition input is empty")
    expected: dict[tuple[str, int, int], tuple[dict[str, Any], dict[str, Any]]] = {}
    for program_id, observations in call_arguments_by_program.items():
        for observation in observations:
            for argument in observation["arguments"]:
                key = (program_id, observation["_record_index"], argument["index"])
                expected[key] = (observation, argument)

    by_program: dict[str, dict[tuple[int, int], dict[str, Any]]] = defaultdict(dict)
    expected_fields = {
        "format", "program_id", "program_sha256", "caller_entry", "callee_entry",
        "call_address", "call_time", "argument_index", "argument_count", "value_token",
        "width_bytes", "resolution_state", "call_observation_ref",
        "call_pcode_evidence_ref", "definition_evidence_refs",
    }
    seen: set[tuple[str, int, int]] = set()
    for definition_index, row in enumerate(rows, 1):
        where = f"call-argument definition record {definition_index}"
        if not isinstance(row, dict) or set(row) != expected_fields:
            raise ValueError(f"{where}: malformed DirectCallArgumentDefinition/1 fields")
        if row.get("format") != CALL_ARGUMENT_DEFINITION_FORMAT:
            raise ValueError(f"{where}: unsupported format")
        observation_ref = row.get("call_observation_ref")
        if not isinstance(observation_ref, dict):
            raise ValueError(f"{where}: malformed call_observation_ref")
        observation_index = observation_ref.get("record_index")
        argument_index = row.get("argument_index")
        if type(observation_index) is not int or observation_index < 1 or type(argument_index) is not int or argument_index < 0:
            raise ValueError(f"{where}: invalid call or argument record index")
        program_id = row.get("program_id")
        if not isinstance(program_id, str) or not program_id:
            raise ValueError(f"{where}: invalid program_id")
        key = (program_id, observation_index, argument_index)
        if key not in expected:
            raise ValueError(f"{where}: definition does not identify an input call argument")
        if key in seen:
            raise ValueError(f"{where}: duplicate definition for input call argument")
        seen.add(key)
        observation, argument = expected[key]
        if row.get("program_sha256") != observation["program_sha256"]:
            raise ValueError(f"{where}: program_sha256 does not match call observation")
        if (
            type(row.get("call_time")) is not int
            or type(row.get("argument_count")) is not int
            or type(row.get("width_bytes")) is not int
        ):
            raise ValueError(f"{where}: call and argument counts/width must be integers")
        for field in ("caller_entry", "callee_entry", "call_address", "call_time", "argument_count"):
            if row.get(field) != observation[field]:
                raise ValueError(f"{where}: {field} does not match call observation")
        if row.get("value_token") != argument["value_token"] or row.get("width_bytes") != argument["width_bytes"]:
            raise ValueError(f"{where}: argument token or width does not match call observation")
        if observation_ref != {
            "artifact_sha256": call_argument_sha256,
            "record_index": observation_index,
            "source_format": CALL_ARGUMENT_FORMAT,
        }:
            raise ValueError(f"{where}: call_observation_ref does not pin the supplied observations")
        if row.get("call_pcode_evidence_ref") != observation["evidence_ref"]:
            raise ValueError(f"{where}: call P-code evidence_ref does not match the observation")

        state = row.get("resolution_state")
        references = row.get("definition_evidence_refs")
        allowed_states = {
            "exact_definition", "definition_not_found", "ambiguous_definition", "non_definition_token",
        }
        if not isinstance(state, str) or state not in allowed_states or not isinstance(references, list):
            raise ValueError(f"{where}: invalid definition resolution")
        expected_count = 1 if state == "exact_definition" else 2 if state == "ambiguous_definition" else 0
        if (state == "ambiguous_definition" and len(references) < expected_count) or (
            state != "ambiguous_definition" and len(references) != expected_count
        ):
            raise ValueError(f"{where}: definition references disagree with resolution state")
        if state == "non_definition_token" and argument["value_token"].startswith("def:"):
            raise ValueError(f"{where}: def token cannot be classified as non-definition")
        if state != "non_definition_token" and not argument["value_token"].startswith("def:"):
            raise ValueError(f"{where}: non-def token cannot have a definition resolution")
        seen_refs: set[tuple[str, int]] = set()
        for reference in references:
            if not isinstance(reference, dict) or set(reference) != {
                "artifact_sha256", "record_index", "source_format",
            }:
                raise ValueError(f"{where}: malformed definition evidence_ref")
            if (
                reference.get("artifact_sha256") != observation["evidence_ref"]["artifact_sha256"]
                or type(reference.get("record_index")) is not int
                or reference["record_index"] < 1
                or reference.get("source_format") != "REVENGINSTR.GhidraFunctionPcodeFlow/1"
            ):
                raise ValueError(f"{where}: definition evidence_ref must use the call's exact P-code artifact")
            reference_key = (reference["artifact_sha256"], reference["record_index"])
            if reference_key in seen_refs:
                raise ValueError(f"{where}: duplicate definition evidence_ref")
            seen_refs.add(reference_key)
        by_program[row["program_id"]][(observation_index, argument_index)] = {
            **row, "_record_index": definition_index,
        }

    if seen != set(expected):
        missing = len(set(expected) - seen)
        raise ValueError(f"DirectCallArgumentDefinition input omits {missing} call arguments")
    return by_program


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
    if graph_format not in {FORMAT_V1, FORMAT_V2, FORMAT_V3, FORMAT_V4}:
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
    if graph_format in {FORMAT_V2, FORMAT_V3, FORMAT_V4}:
        for node in graph["nodes"]:
            if node["kind"] != "receiver_observation":
                continue
            has_edge = node["id"] in observations_with_edges
            expects_edge = node["join_state"] in {"matched", "matched_contested"}
            if has_edge != expects_edge:
                raise ValueError("receiver observation join_state disagrees with graph edges")
    if graph_format in {FORMAT_V3, FORMAT_V4} and (
        graph_format == FORMAT_V3
        or "source_type_layout_hypotheses_format" in graph
        or "source_type_layout_hypotheses_sha256" in graph
    ):
        layout_sha256 = graph.get("source_type_layout_hypotheses_sha256")
        if (
            graph.get("source_type_layout_hypotheses_format") != TYPE_LAYOUT_FORMAT
            or not isinstance(layout_sha256, str)
            or not _is_sha256(layout_sha256)
        ):
            raise ValueError("SemanticProgramGraph/3 requires pinned TypeLayoutHypothesis input")
        type_nodes = {node["id"]: node for node in graph["nodes"] if node["kind"] == "type"}
        field_nodes = {node["id"]: node for node in graph["nodes"] if node["kind"] == "layout_field"}
        if not type_nodes:
            raise ValueError("SemanticProgramGraph/3 requires at least one layout type")
        attached_fields: set[str] = set()
        for edge in graph["edges"]:
            if edge["relation"] != "has_field":
                continue
            field = field_nodes[edge["to"]]
            owner = type_nodes[edge["from"]]
            if field["type_id"] != owner["type_id"] or field["id"] in attached_fields:
                raise ValueError("layout field ownership edge does not match its type")
            attached_fields.add(field["id"])
        if attached_fields != set(field_nodes):
            raise ValueError("layout field must have exactly one owner type")
        for node in (*type_nodes.values(), *field_nodes.values()):
            if node["hypothesis_record_index"] < 1 or not any(
                support.get("provenance", {}).get("source_format") == TYPE_LAYOUT_FORMAT
                and support.get("provenance", {}).get("artifact_sha256") == layout_sha256
                and support.get("provenance", {}).get("record_index") == node["hypothesis_record_index"]
                for support in node["support"]
            ):
                raise ValueError("layout graph node does not reference its pinned hypothesis row")
    if graph_format == FORMAT_V4:
        if (
            graph.get("source_call_arguments_format") != CALL_ARGUMENT_FORMAT
            or not _is_sha256(graph.get("source_call_arguments_sha256", ""))
            or not _is_sha256(graph.get("source_call_arguments_program_sha256", ""))
        ):
            raise ValueError("SemanticProgramGraph/4 requires pinned call-argument input")
        definition_format = graph.get("source_call_argument_definitions_format")
        definition_sha256 = graph.get("source_call_argument_definitions_sha256")
        has_definition_format = definition_format is not None
        has_definition_sha256 = definition_sha256 is not None
        if has_definition_format != has_definition_sha256:
            raise ValueError("call-argument definition pins must include format and SHA-256")
        if has_definition_format and (
            definition_format != CALL_ARGUMENT_DEFINITION_FORMAT
            or not _is_sha256(definition_sha256)
        ):
            raise ValueError("invalid pinned DirectCallArgumentDefinition input")
        seen_definition_record_indices: set[int] = set()
        annotation_fields = {
            "call_argument_count", "call_arguments", "call_argument_callee_entry",
            "call_argument_observation_record_index", "call_argument_source_evidence_ref",
        }
        annotated_nodes = 0
        for node in graph["nodes"]:
            present_fields = annotation_fields & set(node)
            if not present_fields:
                continue
            if present_fields != annotation_fields:
                raise ValueError("call-argument annotation must include all provenance and value fields")
            annotated_nodes += 1
            arguments = node.get("call_arguments")
            count = node.get("call_argument_count")
            record_index = node.get("call_argument_observation_record_index")
            if (
                node.get("kind") != "operation"
                or node.get("opcode") != "CALL"
                or node.get("call_target_state") != "resolved"
                or type(count) is not int
                or not isinstance(arguments, list)
                or count != len(arguments)
                or type(record_index) is not int
                or record_index < 1
            ):
                raise ValueError("call arguments must attach to one resolved CALL operation")
            if node.get("target_entries") != [node.get("call_argument_callee_entry")]:
                raise ValueError("call-argument callee does not match resolved CALL target")
            source_ref = node.get("call_argument_source_evidence_ref")
            if not isinstance(source_ref, dict) or set(source_ref) != {
                "artifact_sha256", "record_index", "source_format",
            }:
                raise ValueError("call arguments lack their source P-code evidence_ref")
            for index, argument in enumerate(arguments):
                base_argument_fields = {"index", "value_token", "width_bytes"}
                definition_argument_fields = {
                    "definition_resolution_state", "definition_analysis_record_index",
                    "definition_evidence_refs",
                }
                required_argument_fields = (
                    base_argument_fields | definition_argument_fields
                    if has_definition_format else base_argument_fields
                )
                if (
                    not isinstance(argument, dict)
                    or set(argument) != required_argument_fields
                    or type(argument.get("index")) is not int
                    or argument["index"] != index
                    or not isinstance(argument.get("value_token"), str)
                    or type(argument.get("width_bytes")) is not int
                    or argument["width_bytes"] < 1
                ):
                    raise ValueError("call-argument list is malformed")
                if has_definition_format:
                    state = argument["definition_resolution_state"]
                    references = argument["definition_evidence_refs"]
                    if (
                        not isinstance(state, str)
                        or state not in {
                            "exact_definition", "definition_not_found", "ambiguous_definition",
                            "non_definition_token",
                        }
                        or type(argument["definition_analysis_record_index"]) is not int
                        or argument["definition_analysis_record_index"] < 1
                        or not isinstance(references, list)
                    ):
                        raise ValueError("call-argument definition annotation is malformed")
                    expected_count = 1 if state == "exact_definition" else 2 if state == "ambiguous_definition" else 0
                    if (state == "ambiguous_definition" and len(references) < expected_count) or (
                        state != "ambiguous_definition" and len(references) != expected_count
                    ):
                        raise ValueError("call-argument definition refs disagree with resolution state")
                    if state == "non_definition_token" and argument["value_token"].startswith("def:"):
                        raise ValueError("def token cannot be classified as non-definition")
                    if state != "non_definition_token" and not argument["value_token"].startswith("def:"):
                        raise ValueError("non-def token cannot have a definition resolution")
                    definition_record_index = argument["definition_analysis_record_index"]
                    if definition_record_index in seen_definition_record_indices:
                        raise ValueError("duplicate call-argument definition analysis record index")
                    seen_definition_record_indices.add(definition_record_index)
                    seen_definition_refs: set[tuple[str, int]] = set()
                    for reference in references:
                        if not isinstance(reference, dict) or set(reference) != {
                            "artifact_sha256", "record_index", "source_format",
                        } or (
                            reference.get("artifact_sha256") != source_ref["artifact_sha256"]
                            or type(reference.get("record_index")) is not int
                            or reference["record_index"] < 1
                            or reference.get("source_format") != "REVENGINSTR.GhidraFunctionPcodeFlow/1"
                        ):
                            raise ValueError("call-argument definition ref must match the call P-code artifact")
                        reference_key = (reference["artifact_sha256"], reference["record_index"])
                        if reference_key in seen_definition_refs:
                            raise ValueError("duplicate call-argument definition evidence ref")
                        seen_definition_refs.add(reference_key)
            if (
                source_ref.get("source_format") != "REVENGINSTR.GhidraFunctionPcodeFlow/1"
                or not _is_sha256(source_ref.get("artifact_sha256", ""))
                or type(source_ref.get("record_index")) is not int
                or source_ref["record_index"] < 1
                or not any(
                    support.get("provenance", {}).get("source_format") == source_ref["source_format"]
                    and support.get("provenance", {}).get("artifact_sha256") == source_ref["artifact_sha256"]
                    and support.get("provenance", {}).get("record_index") == source_ref["record_index"]
                    for support in node["support"]
                )
            ):
                raise ValueError("call-argument P-code reference must match operation support")
        if annotated_nodes == 0:
            raise ValueError("SemanticProgramGraph/4 requires at least one attached call-argument observation")
    elif any(
        "call_argument_observation_record_index" in node
        or "call_arguments" in node
        or "source_call_argument_definitions_format" in graph
        or "source_call_argument_definitions_sha256" in graph
        for node in graph["nodes"]
    ):
        raise ValueError("call-argument observations require SemanticProgramGraph/4")


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
    type_layout_rows: list[dict[str, Any]] | None = None,
    type_layout_sha256: str | None = None,
    call_argument_rows: list[dict[str, Any]] | None = None,
    call_argument_sha256: str | None = None,
    call_argument_definition_rows: list[dict[str, Any]] | None = None,
    call_argument_definition_sha256: str | None = None,
) -> list[dict[str, Any]]:
    """Project effects, optional receiver/layout evidence, and call arguments."""
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
    layout_by_program: dict[str, list[dict[str, Any]]] = defaultdict(list)
    if type_layout_rows is not None:
        if type_layout_sha256 is None or not _is_sha256(type_layout_sha256):
            raise ValueError("type-layout hypotheses require their source SHA-256")
        layout_by_program = _validate_type_layout_rows(
            type_layout_rows, known_programs=set(by_program)
        )
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
    call_arguments_by_program: dict[str, list[dict[str, Any]]] = defaultdict(list)
    call_argument_program_hashes: dict[str, str] = {}
    if call_argument_rows is not None:
        if call_argument_sha256 is None or not _is_sha256(call_argument_sha256):
            raise ValueError("call arguments require their source SHA-256")
        call_arguments_by_program, call_argument_program_hashes = _validate_call_argument_rows(
            call_argument_rows, known_programs=set(by_program)
        )
        for program_id, layouts in layout_by_program.items():
            if program_id in call_argument_program_hashes and any(
                row["program_sha256"] != call_argument_program_hashes[program_id]
                for row in layouts
            ):
                raise ValueError("call-argument program_sha256 does not match type-layout program_sha256")
    call_argument_definitions_by_program: dict[str, dict[tuple[int, int], dict[str, Any]]] = defaultdict(dict)
    if call_argument_definition_rows is not None:
        if call_argument_rows is None or call_argument_sha256 is None:
            raise ValueError("call-argument definitions require pinned call-argument observations")
        if call_argument_definition_sha256 is None or not _is_sha256(call_argument_definition_sha256):
            raise ValueError("call-argument definitions require their source SHA-256")
        call_argument_definitions_by_program = _validate_call_argument_definition_rows(
            call_argument_definition_rows,
            call_arguments_by_program=call_arguments_by_program,
            call_argument_sha256=call_argument_sha256,
        )
    elif call_argument_definition_sha256 is not None:
        raise ValueError("call-argument definition SHA-256 supplied without definition rows")

    graphs: list[dict[str, Any]] = []
    for program_id, functions in sorted(by_program.items()):
        program_call_arguments = call_arguments_by_program.get(program_id, [])
        program_call_argument_definitions = call_argument_definitions_by_program.get(program_id, {})
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

        for row in program_call_arguments:
            same_site = operations_by_site.get((
                row["caller_entry"], row["call_address"], row["call_time"],
            ), [])
            candidates = [
                operation for operation in same_site
                if operation.get("opcode") == "CALL"
                and operation.get("call_target_state") == "resolved"
                and operation.get("target_entries") == [row["callee_entry"]]
            ]
            if len(candidates) != 1:
                raise ValueError(
                    "call-argument observation does not match one exact resolved CALL site: "
                    f"{row['caller_entry']}:{row['call_address']}#{row['call_time']}"
                )
            operation = candidates[0]
            source_ref = row["evidence_ref"]
            if not any(
                support.get("provenance") == source_ref
                for support in operation["support"]
            ):
                raise ValueError(
                    "call-argument evidence_ref does not match the CALL operation P-code source"
                )
            operation["call_argument_count"] = row["argument_count"]
            operation["call_arguments"] = []
            for argument in row["arguments"]:
                graph_argument = dict(argument)
                if call_argument_definition_rows is not None:
                    definition = program_call_argument_definitions[(row["_record_index"], argument["index"])]
                    graph_argument.update({
                        "definition_resolution_state": definition["resolution_state"],
                        "definition_analysis_record_index": definition["_record_index"],
                        "definition_evidence_refs": definition["definition_evidence_refs"],
                    })
                operation["call_arguments"].append(graph_argument)
            operation["call_argument_callee_entry"] = row["callee_entry"]
            operation["call_argument_observation_record_index"] = row["_record_index"]
            operation["call_argument_source_evidence_ref"] = source_ref

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

        for row in layout_by_program.get(program_id, []):
            record_index = row["_record_index"]
            support = _layout_support(
                row, source_sha256=type_layout_sha256, record_index=record_index
            )
            all_support.append(support)
            type_node = _stable_id("type", [program_id, row["type_id"]])
            type_conflicted = row["status"] == "conflicted" or bool(row["conflicts"])
            _add_node(nodes, {
                "id": type_node,
                "kind": "type",
                "type_id": row["type_id"],
                "status": row["status"],
                "conflict_reasons": ["type_layout_conflict"] if type_conflicted else [],
                "architecture": row["architecture"],
                "object_size": row["object_size"],
                "vtable_anchors": row["vtable_anchors"],
                "relationships": row["relationships"],
                "conflicts": row["conflicts"],
                "hypothesis_record_index": record_index,
                "evidence_class": "derived_structural",
                "support": [support],
                "confidence": None,
                "conflict_state": "contested" if type_conflicted else "uncontested",
            })
            for field in row["fields"]:
                field_conflicted = field["status"] == "conflicted" or bool(field["conflicts"])
                field_node = _stable_id(
                    "layout_field", [program_id, row["type_id"], field["offset_bytes"]]
                )
                field_support = {
                    **support,
                    "source_record_id": f"{row['type_id']}+0x{field['offset_bytes']:x}#{record_index}",
                }
                _add_node(nodes, {
                    "id": field_node,
                    "kind": "layout_field",
                    "type_id": row["type_id"],
                    "offset_bytes": field["offset_bytes"],
                    "status": field["status"],
                    "conflict_reasons": ["field_layout_conflict"] if field_conflicted else [],
                    "accesses": field["accesses"],
                    "type_candidates": field["type_candidates"],
                    "conflicts": field["conflicts"],
                    "hypothesis_record_index": record_index,
                    "evidence_class": "derived_structural",
                    "support": [field_support],
                    "confidence": None,
                    "conflict_state": "contested" if field_conflicted else "uncontested",
                })
                _add_edge(edges, {
                    "from": type_node,
                    "to": field_node,
                    "relation": "has_field",
                    "evidence_class": "derived_structural",
                    "support": [field_support],
                    "confidence": None,
                    "conflict_state": "uncontested",
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
            if node["kind"] == "function" or (
                node["kind"] == "type" and type_layout_rows is not None
            ):
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
            "format": (
                FORMAT_V4 if program_call_arguments
                else FORMAT_V3 if type_layout_rows is not None
                else FORMAT_V2 if receiver_rows is not None
                else FORMAT_V1
            ),
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
        if type_layout_rows is not None:
            graph["source_type_layout_hypotheses_format"] = TYPE_LAYOUT_FORMAT
            graph["source_type_layout_hypotheses_sha256"] = type_layout_sha256
        if program_call_arguments:
            graph["source_call_arguments_format"] = CALL_ARGUMENT_FORMAT
            graph["source_call_arguments_sha256"] = call_argument_sha256
            graph["source_call_arguments_program_sha256"] = call_argument_program_hashes[program_id]
        if call_argument_definition_rows is not None and program_call_arguments:
            graph["source_call_argument_definitions_format"] = CALL_ARGUMENT_DEFINITION_FORMAT
            graph["source_call_argument_definitions_sha256"] = call_argument_definition_sha256
        graph = {
            key: graph[key]
            for key in (
                "format", "graph_id", "program_id", "source_effect_ir_format",
                "source_effect_ir_sha256", "source_receiver_types_format",
                "source_receiver_types_sha256", "source_type_layout_hypotheses_format",
                "source_type_layout_hypotheses_sha256", "source_call_arguments_format",
                "source_call_arguments_sha256", "source_call_arguments_program_sha256",
                "source_call_argument_definitions_format", "source_call_argument_definitions_sha256",
                "nodes", "edges",
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
    parser.add_argument(
        "--type-layout-hypotheses", type=Path,
        help="optional TypeLayoutHypothesis/1 JSONL; adds candidate type and field nodes",
    )
    parser.add_argument(
        "--call-arguments", type=Path,
        help="optional DirectCallArgumentObservation/1 JSONL; joins exact resolved CALL sites",
    )
    parser.add_argument(
        "--call-argument-definitions", type=Path,
        help="optional DirectCallArgumentDefinition/1 JSONL; pins exact argument definition rows",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    records, source_sha256 = _read_jsonl(args.function_effect_ir)
    receiver_rows = None
    receiver_sha256 = None
    if args.receiver_types is not None:
        receiver_rows, receiver_sha256 = _read_receiver_types(args.receiver_types)
    type_layout_rows = None
    type_layout_sha256 = None
    if args.type_layout_hypotheses is not None:
        type_layout_rows, type_layout_sha256 = _read_jsonl(args.type_layout_hypotheses)
    call_argument_rows = None
    call_argument_sha256 = None
    if args.call_arguments is not None:
        call_argument_rows, call_argument_sha256 = _read_jsonl(args.call_arguments)
    call_argument_definition_rows = None
    call_argument_definition_sha256 = None
    if args.call_argument_definitions is not None:
        call_argument_definition_rows, call_argument_definition_sha256 = _read_jsonl(args.call_argument_definitions)
    graphs = build_semantic_program_graphs(
        records,
        source_sha256=source_sha256,
        receiver_rows=receiver_rows,
        receiver_sha256=receiver_sha256,
        type_layout_rows=type_layout_rows,
        type_layout_sha256=type_layout_sha256,
        call_argument_rows=call_argument_rows,
        call_argument_sha256=call_argument_sha256,
        call_argument_definition_rows=call_argument_definition_rows,
        call_argument_definition_sha256=call_argument_definition_sha256,
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
    if type_layout_sha256 is not None:
        print("source type-layout hypotheses SHA-256:", type_layout_sha256)
        print("layout types:", sum(
            node["kind"] == "type" for graph in graphs for node in graph["nodes"]
        ))
        print("layout fields:", sum(
            node["kind"] == "layout_field" for graph in graphs for node in graph["nodes"]
        ))
    if call_argument_sha256 is not None:
        print("source call-argument observations SHA-256:", call_argument_sha256)
        print("call sites with argument observations:", sum(
            "call_argument_observation_record_index" in node
            for graph in graphs for node in graph["nodes"]
        ))
    if call_argument_definition_sha256 is not None:
        print("source call-argument definitions SHA-256:", call_argument_definition_sha256)
    print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
