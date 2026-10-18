"""Audit same-field accesses for a bounded safe High-P-code CFG path."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import deque
from pathlib import Path
from typing import Any

from revenginstr.pcode.opcodes import NO_EXPLICIT_MEMORY_WRITE_OPCODES
from .provenance import FORMAT as GRAPH_FORMAT
from .provenance import PARAMETER_LOAD_FORMAT, PARAMETER_STORE_FORMAT, validate_graph_references

FORMAT = "REVENGINSTR.FieldStoreLoadPathAudit/1"
CFG_FORMAT = "REVENGINSTR.GhidraFunctionPcodeCFG/1"
CFG_FORMAT_V2 = "REVENGINSTR.GhidraFunctionPcodeCFG/2"
CFG_FORMAT_V3 = "REVENGINSTR.GhidraFunctionPcodeCFG/3"
CFG_FORMAT_V4 = "REVENGINSTR.GhidraFunctionPcodeCFG/4"
REACHING_FORMAT = "REVENGINSTR.FieldStoreLoadDominanceAudit/1"
REACHING_FORMAT_V2 = "REVENGINSTR.FieldStoreLoadDominanceAudit/2"
REACHING_FORMAT_V3 = "REVENGINSTR.FieldStoreLoadDominanceAudit/3"
REACHING_FORMAT_V4 = "REVENGINSTR.FieldStoreLoadDominanceAudit/4"
REACHING_FORMAT_V5 = "REVENGINSTR.FieldStoreLoadDominanceAudit/5"
REACHING_FORMAT_V6 = "REVENGINSTR.FieldStoreLoadDominanceAudit/6"
MEMORY_STORE_ACCESS_FORMAT = "REVENGINSTR.GhidraMemoryStoreAccess/1"
DIRECT_CALL_MEMORY_EFFECT_FORMAT = "REVENGINSTR.GhidraDirectCallMemoryEffect/1"
DIRECT_CALL_MEMORY_EFFECT_CLOSURE_FORMAT = "REVENGINSTR.GhidraDirectCallMemoryEffectClosure/1"
INTERPROCEDURAL_MEMORY_EFFECT_FORMAT = "REVENGINSTR.GhidraInterproceduralMemoryEffect/1"
INTERPROCEDURAL_MEMORY_EFFECT_FORMAT_V2 = "REVENGINSTR.GhidraInterproceduralMemoryEffect/2"
REACHING_CLAIM_SCOPE_V2 = (
    "Conservative single-function High-P-code structural candidate; only known different physical spaces "
    "and same-root non-overlapping byte ranges are excluded; no branch-feasibility or runtime value-flow claim."
)
REACHING_CLAIM_SCOPE_V3 = (
    "Conservative single-function High-P-code structural candidate; only known different physical spaces, "
    "same-root non-overlapping byte ranges, and directly resolved calls with complete write-free P-code "
    "summaries are excluded; no branch-feasibility or runtime value-flow claim."
)
REACHING_CLAIM_SCOPE_V4 = (
    "Conservative single-function High-P-code structural candidate; only known different physical spaces, "
    "same-root non-overlapping byte ranges, and direct calls with complete, hash-pinned transitive "
    "write-free P-code closures are excluded; no branch-feasibility or runtime value-flow claim."
)
REACHING_CLAIM_SCOPE_V5 = (
    "Conservative single-function High-P-code structural candidate; direct calls are excluded only when a "
    "hash-pinned interprocedural audit proves every reachable STORE is outside the tracked byte range; "
    "missing argument roots, unresolved stores, indirect calls, unknown operations, and incomplete closures "
    "remain barriers; no branch-feasibility or runtime value-flow claim."
)
REACHING_CLAIM_SCOPE_V6 = (
    "Conservative single-function High-P-code structural candidate; source-linked INDIRECT markers are counted "
    "with their exact source operation and ignored only when that operation is classified harmless; direct calls "
    "remain barriers without complete effect evidence; no branch-feasibility or runtime value-flow claim."
)
HAZARD_OPCODES = {"STORE", "CALL", "CALLIND", "CALLOTHER"}
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _read_jsonl(path: Path) -> tuple[str, list[dict[str, Any]]]:
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"{path}: input must be UTF-8") from error
    rows = []
    for line_no, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            raise ValueError(f"{path}:{line_no}: blank JSONL record")
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"{path}:{line_no}: invalid JSON") from error
        if not isinstance(row, dict):
            raise ValueError(f"{path}:{line_no}: expected object")
        rows.append(row)
    return hashlib.sha256(raw).hexdigest(), rows


def _int(value: Any, where: str, *, nullable: bool = False) -> int | None:
    if nullable and value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{where}: expected non-negative integer")
    return value


def _parse_source_id(value: Any, source_format: str, where: str) -> list[Any]:
    if not isinstance(value, str):
        raise ValueError(f"{where}: missing source id")
    try:
        key = json.loads(value)
    except json.JSONDecodeError as error:
        raise ValueError(f"{where}: invalid source id") from error
    if not isinstance(key, list) or len(key) != 7:
        raise ValueError(f"{where}: unexpected source identity")
    if any(not isinstance(key[index], str) or not key[index] for index in (0, 1, 2)):
        raise ValueError(f"{where}: invalid program/function/address identity")
    _int(key[3], f"{where} operation time", nullable=True)
    _int(key[4], f"{where} parameter index")
    if not isinstance(key[5], int) or isinstance(key[5], bool):
        raise ValueError(f"{where}: invalid field offset")
    if source_format == PARAMETER_STORE_FORMAT:
        _int(key[6], f"{where} source parameter index")
    elif not isinstance(key[6], str) or not key[6]:
        raise ValueError(f"{where}: invalid load value token")
    return key


def _pair_identity(graph: dict[str, Any], row: int) -> dict[str, Any]:
    where = f"field-access pair {row}"
    if graph.get("format") != GRAPH_FORMAT or not isinstance(graph.get("graph_id"), str):
        raise ValueError(f"{where}: unsupported graph")
    edges = graph.get("edges")
    if (
        not isinstance(graph.get("nodes"), list)
        or not isinstance(edges, list)
        or any(
            not isinstance(edge, dict)
            or not isinstance(edge.get("provenance"), list)
            or any(not isinstance(item, dict) for item in edge["provenance"])
            for edge in edges
        )
    ):
        raise ValueError(f"{where}: malformed graph shape")
    try:
        validate_graph_references(graph)
    except (AttributeError, KeyError, TypeError) as error:
        raise ValueError(f"{where}: malformed graph references") from error
    store_refs = [
        provenance for edge in edges if edge.get("relation") == "field_store"
        for provenance in edge.get("provenance", [])
        if provenance.get("source_format") == PARAMETER_STORE_FORMAT
    ]
    load_refs = [
        provenance for edge in edges if edge.get("relation") == "field_load"
        for provenance in edge.get("provenance", [])
        if provenance.get("source_format") == PARAMETER_LOAD_FORMAT
    ]
    if len(store_refs) != 1 or len(load_refs) != 1:
        raise ValueError(f"{where}: expected one field-store and one field-load reference")
    store_id, load_id = store_refs[0].get("source_id"), load_refs[0].get("source_id")
    store_key = _parse_source_id(store_id, PARAMETER_STORE_FORMAT, f"{where} store")
    load_key = _parse_source_id(load_id, PARAMETER_LOAD_FORMAT, f"{where} load")
    try:
        graph_id = json.loads(graph["graph_id"])
    except json.JSONDecodeError as error:
        raise ValueError(f"{where}: invalid graph id") from error
    program_id = store_key[0]
    if (
        not isinstance(graph_id, list) or len(graph_id) != 3
        or graph_id != [program_id, store_id, load_id]
        or store_key[1] != load_key[1]
        or store_key[4:6] != load_key[4:6]
        or load_key[0] != program_id
    ):
        raise ValueError(f"{where}: field pair identity mismatch")
    return {
        "program_id": program_id,
        "function_entry": store_key[1],
        "parameter_index": store_key[4],
        "field_offset": store_key[5],
        "source_parameter_index": store_key[6],
        "store_address": store_key[2],
        "store_time": store_key[3],
        "load_address": load_key[2],
        "load_time": load_key[3],
        "store_source_id": store_id,
        "load_source_id": load_id,
    }


def _index_cfg(
    records: list[dict[str, Any]],
) -> dict[tuple[str, str], tuple[int, dict[str, Any]]]:
    indexed = {}
    for record_index, record in enumerate(records, 1):
        where = f"P-code CFG record {record_index}"
        cfg_format = record.get("format") if isinstance(record, dict) else None
        has_memory_metadata = cfg_format in {CFG_FORMAT_V2, CFG_FORMAT_V3, CFG_FORMAT_V4}
        v3 = cfg_format in {CFG_FORMAT_V3, CFG_FORMAT_V4}
        v4 = cfg_format == CFG_FORMAT_V4
        expected_record_fields = (
            {"format", "program_id", "function_entry", "entry_block_index", "blocks"}
            if has_memory_metadata else {"format", "program_id", "function_entry", "blocks"}
        )
        if (
            not isinstance(record, dict)
            or set(record) != expected_record_fields
            or cfg_format not in {CFG_FORMAT, CFG_FORMAT_V2, CFG_FORMAT_V3, CFG_FORMAT_V4}
            or not isinstance(record.get("program_id"), str)
            or not record["program_id"]
            or not isinstance(record.get("function_entry"), str)
            or not record["function_entry"]
            or not isinstance(record.get("blocks"), list)
        ):
            raise ValueError(f"{where}: unexpected format or fields")
        function_entry = record["function_entry"]
        identity_key = (record["program_id"], function_entry)
        if identity_key in indexed:
            raise ValueError(f"{where}: duplicate program/function identity")
        entry_block_index = _int(record["entry_block_index"], f"{where} entry block") if has_memory_metadata else None
        blocks: dict[int, dict[str, Any]] = {}
        operations: dict[tuple[str, int], tuple[int, int, str]] = {}
        operation_details: dict[tuple[str, int], dict[str, Any]] = {}
        address_space_metadata: dict[str, tuple[str | None, int | None]] = {}
        indirect_links: list[tuple[tuple[str, int], tuple[str, int, str]]] = []
        for block in record["blocks"]:
            if (
                not isinstance(block, dict)
                or set(block) != {"block_index", "start_address", "stop_address", "operations", "successors"}
            ):
                raise ValueError(f"{where}: malformed block")
            block_index = _int(block["block_index"], f"{where} block index")
            if block_index in blocks:
                raise ValueError(f"{where}: duplicate block index")
            if any(not isinstance(block[key], str) or not block[key] for key in ("start_address", "stop_address")):
                raise ValueError(f"{where}: invalid block bounds")
            if not isinstance(block["operations"], list) or not isinstance(block["successors"], list):
                raise ValueError(f"{where}: invalid block operations or successors")
            block_operations = []
            for position, operation in enumerate(block["operations"]):
                expected_operation_fields = (
                    {"address", "time", "opcode", "memory_space", "memory_width_bytes",
                     "memory_physical_space", "memory_pointer_width_bytes", "indirect_effect_link"}
                    if v4 else {"address", "time", "opcode", "memory_space", "memory_width_bytes",
                                "memory_physical_space", "memory_pointer_width_bytes"}
                    if v3 else {"address", "time", "opcode", "memory_space", "memory_width_bytes"}
                    if has_memory_metadata else {"address", "time", "opcode"}
                )
                if not isinstance(operation, dict) or set(operation) != expected_operation_fields:
                    raise ValueError(f"{where}: malformed operation")
                if not isinstance(operation["address"], str) or not operation["address"]:
                    raise ValueError(f"{where}: invalid operation address")
                operation_time = _int(operation["time"], f"{where} operation time")
                if not isinstance(operation["opcode"], str) or not operation["opcode"]:
                    raise ValueError(f"{where}: invalid opcode")
                if v4:
                    link = operation["indirect_effect_link"]
                    if operation["opcode"] == "INDIRECT":
                        if not isinstance(link, dict) or set(link) != {
                            "status", "source_address", "source_time", "source_opcode",
                        }:
                            raise ValueError(f"{where}: malformed INDIRECT effect link")
                        if link["status"] == "resolved":
                            if (
                                not isinstance(link["source_address"], str) or not link["source_address"]
                                or not isinstance(link["source_opcode"], str) or not link["source_opcode"]
                            ):
                                raise ValueError(f"{where}: invalid resolved INDIRECT effect source")
                            source_time = _int(link["source_time"], f"{where} INDIRECT source time")
                            marker_key = (operation["address"], operation_time)
                            indirect_links.append((marker_key, (link["source_address"], source_time, link["source_opcode"])))
                        elif link["status"] == "unresolved":
                            if any(link[key] is not None for key in ("source_address", "source_time", "source_opcode")):
                                raise ValueError(f"{where}: unresolved INDIRECT link must not identify a source")
                        else:
                            raise ValueError(f"{where}: invalid INDIRECT effect link status")
                    elif link is not None:
                        raise ValueError(f"{where}: non-INDIRECT operation has an effect link")
                if has_memory_metadata:
                    memory_space = operation["memory_space"]
                    memory_width = operation["memory_width_bytes"]
                    if memory_space is not None and (not isinstance(memory_space, str) or not memory_space):
                        raise ValueError(f"{where}: invalid memory space")
                    if memory_width is not None and _int(memory_width, f"{where} memory width") == 0:
                        raise ValueError(f"{where}: memory width must be positive")
                    memory_metadata = [memory_space, memory_width]
                    if v3:
                        physical_space = operation["memory_physical_space"]
                        pointer_width = operation["memory_pointer_width_bytes"]
                        if physical_space is not None and (not isinstance(physical_space, str) or not physical_space):
                            raise ValueError(f"{where}: invalid physical memory space")
                        if pointer_width is not None and _int(pointer_width, f"{where} memory pointer width") == 0:
                            raise ValueError(f"{where}: memory pointer width must be positive")
                        if memory_space is None and (physical_space is not None or pointer_width is not None):
                            raise ValueError(f"{where}: physical memory metadata lacks a logical space")
                        if memory_space is not None:
                            previous = address_space_metadata.get(memory_space)
                            if previous is not None and any(
                                old is not None and new is not None and old != new
                                for old, new in zip(previous, (physical_space, pointer_width))
                            ):
                                raise ValueError(f"{where}: inconsistent metadata for logical space {memory_space!r}")
                            address_space_metadata[memory_space] = (
                                physical_space if physical_space is not None else (None if previous is None else previous[0]),
                                pointer_width if pointer_width is not None else (None if previous is None else previous[1]),
                            )
                        memory_metadata.extend([physical_space, pointer_width])
                    if operation["opcode"] not in {"LOAD", "STORE"} and any(value is not None for value in memory_metadata):
                        raise ValueError(f"{where}: non-memory operation has memory metadata")
                key = (operation["address"], operation_time)
                if key in operations:
                    raise ValueError(f"{where}: duplicate operation location")
                operations[key] = (block_index, position, operation["opcode"])
                operation_details[key] = operation
                block_operations.append(operation)
            successors = [_int(value, f"{where} successor") for value in block["successors"]]
            if len(successors) != len(set(successors)):
                raise ValueError(f"{where}: duplicate successor")
            blocks[block_index] = {
                "start_address": block["start_address"],
                "operations": block_operations,
                "successors": successors,
            }
        for block_index, block in blocks.items():
            if any(successor not in blocks for successor in block["successors"]):
                raise ValueError(f"{where} block {block_index}: dangling successor")
        for marker_key, (source_address, source_time, source_opcode) in indirect_links:
            source_key = (source_address, source_time)
            source_operation = operations.get(source_key)
            if (
                source_key == marker_key or source_operation is None
                or source_operation[2] != source_opcode
            ):
                raise ValueError(f"{where}: INDIRECT effect link does not match a distinct CFG operation")
        if has_memory_metadata and (entry_block_index not in blocks or blocks[entry_block_index]["start_address"] != function_entry):
            raise ValueError(f"{where}: entry block does not start at the function entry")
        indexed[identity_key] = (record_index, {
            "format": cfg_format,
            "entry_block_index": entry_block_index,
            "blocks": blocks,
            "operations": operations,
            "operation_details": operation_details,
        })
    return indexed


def _index_memory_store_accesses(
    records: list[dict[str, Any]],
    cfg_by_function: dict[tuple[str, str], tuple[int, dict[str, Any]]],
) -> tuple[
    dict[tuple[str, str, str, int], dict[str, Any]],
    dict[tuple[str, str], list[int]],
    dict[tuple[str, str, str, int], int],
]:
    indexed: dict[tuple[str, str, str, int], dict[str, Any]] = {}
    indices_by_function: dict[tuple[str, str], list[int]] = {}
    record_indices: dict[tuple[str, str, str, int], int] = {}
    space_metadata: dict[tuple[str, str], tuple[str | None, int | None, int | None, int | None]] = {}
    expected_fields = {
        "format", "program_id", "function_entry", "address", "time", "opcode",
        "memory_space", "memory_physical_space", "memory_width_bytes",
        "memory_pointer_width_bytes", "memory_space_size_bits",
        "memory_addressable_unit_bytes", "pointer_token", "root_parameter_index",
        "offset_bytes", "location_status", "destination_pattern", "address_expression_ops",
    }
    for record_index, fact in enumerate(records, 1):
        where = f"memory store access record {record_index}"
        if (
            not isinstance(fact, dict)
            or set(fact) != expected_fields
            or fact.get("format") != MEMORY_STORE_ACCESS_FORMAT
            or fact.get("opcode") != "STORE"
        ):
            raise ValueError(f"{where}: unexpected format or fields")
        if any(not isinstance(fact.get(key), str) or not fact[key] for key in ("program_id", "function_entry", "address")):
            raise ValueError(f"{where}: invalid operation identity")
        time = _int(fact.get("time"), f"{where} operation time")
        for key in ("memory_space", "memory_physical_space"):
            value = fact[key]
            if value is not None and (not isinstance(value, str) or not value):
                raise ValueError(f"{where}: invalid {key}")
        for key in (
            "memory_width_bytes", "memory_pointer_width_bytes",
            "memory_space_size_bits", "memory_addressable_unit_bytes",
        ):
            value = fact[key]
            if value is not None and _int(value, f"{where} {key}") == 0:
                raise ValueError(f"{where}: {key} must be positive")
        root_parameter = fact["root_parameter_index"]
        if root_parameter is not None:
            _int(root_parameter, f"{where} root parameter")
        offset = fact["offset_bytes"]
        if offset is not None and (not isinstance(offset, int) or isinstance(offset, bool)):
            raise ValueError(f"{where}: invalid byte offset")
        if not isinstance(fact["location_status"], str) or fact["location_status"] not in {
            "parameter_rooted_constant_offset", "unresolved",
        }:
            raise ValueError(f"{where}: invalid location status")
        if fact["location_status"] == "parameter_rooted_constant_offset" and any(
            fact[key] is None for key in (
                "memory_space", "memory_width_bytes", "memory_pointer_width_bytes",
                "memory_space_size_bits", "memory_addressable_unit_bytes",
                "root_parameter_index", "offset_bytes",
            )
        ):
            raise ValueError(f"{where}: resolved location is missing required fields")
        for key in ("pointer_token", "destination_pattern"):
            if not isinstance(fact[key], str) or not fact[key]:
                raise ValueError(f"{where}: invalid {key}")
        derivation = fact["address_expression_ops"]
        if not isinstance(derivation, list):
            raise ValueError(f"{where}: invalid address expression operations")
        for operation_ref in derivation:
            if (
                not isinstance(operation_ref, dict)
                or set(operation_ref) != {"address", "time", "opcode"}
                or not isinstance(operation_ref.get("address"), str)
                or not operation_ref["address"]
                or not isinstance(operation_ref.get("opcode"), str)
                or not operation_ref["opcode"]
            ):
                raise ValueError(f"{where}: malformed address expression operation")
            _int(operation_ref.get("time"), f"{where} address expression operation time")

        program_id = fact["program_id"]
        function_entry = fact["function_entry"]
        function_key = (program_id, function_entry)
        key = (program_id, function_entry, fact["address"], time)
        if key in indexed:
            raise ValueError(f"{where}: duplicate operation identity")
        cfg_item = cfg_by_function.get(function_key)
        if cfg_item is None:
            raise ValueError(f"{where}: missing CFG for program {program_id} function {function_entry}")
        cfg = cfg_item[1]
        operation_location = cfg["operations"].get((fact["address"], time))
        if operation_location is None or operation_location[2] != "STORE":
            raise ValueError(f"{where}: operation does not match CFG STORE")
        if cfg["format"] in {CFG_FORMAT_V2, CFG_FORMAT_V3, CFG_FORMAT_V4}:
            cfg_detail = cfg["operation_details"][(fact["address"], time)]
            if fact["memory_space"] != cfg_detail["memory_space"] or fact["memory_width_bytes"] != cfg_detail["memory_width_bytes"]:
                raise ValueError(f"{where}: memory shape disagrees with CFG")
            if cfg["format"] in {CFG_FORMAT_V3, CFG_FORMAT_V4} and (
                fact["memory_physical_space"] != cfg_detail["memory_physical_space"]
                or fact["memory_pointer_width_bytes"] != cfg_detail["memory_pointer_width_bytes"]
            ):
                raise ValueError(f"{where}: physical memory metadata disagrees with CFG/3")
        for operation_ref in derivation:
            ref_location = cfg["operations"].get((operation_ref["address"], operation_ref["time"]))
            if ref_location is None or ref_location[2] != operation_ref["opcode"]:
                raise ValueError(f"{where}: address derivation does not match CFG operation")
        indices_by_function.setdefault(function_key, []).append(record_index)

        memory_space = fact["memory_space"]
        if memory_space is not None:
            space_key = (program_id, memory_space)
            current = (
                fact["memory_physical_space"], fact["memory_pointer_width_bytes"],
                fact["memory_space_size_bits"], fact["memory_addressable_unit_bytes"],
            )
            previous = space_metadata.get(space_key)
            if previous is not None and any(
                old is not None and new is not None and old != new
                for old, new in zip(previous, current)
            ):
                raise ValueError(f"{where}: inconsistent metadata for logical space {memory_space!r}")
            if previous is None:
                space_metadata[space_key] = current
            else:
                space_metadata[space_key] = tuple(
                    new if new is not None else old for old, new in zip(previous, current)
                )
        indexed[key] = fact
        record_indices[key] = record_index
    return indexed, indices_by_function, record_indices


def _index_direct_call_memory_effects(
    records: list[dict[str, Any]],
    cfg_by_function: dict[tuple[str, str], tuple[int, dict[str, Any]]],
) -> tuple[dict[tuple[str, str, str, int], dict[str, Any]], dict[tuple[str, str], list[int]]]:
    indexed: dict[tuple[str, str, str, int], dict[str, Any]] = {}
    indices_by_function: dict[tuple[str, str], list[int]] = {}
    expected_fields = {
        "format", "program_id", "function_entry", "address", "time", "opcode",
        "callee_entry", "status", "effect_opcodes", "provenance",
    }
    expected_provenance = {
        "caller_pcode_flow_sha256", "caller_pcode_flow_record_index",
        "callee_pcode_flow_sha256", "callee_pcode_flow_record_count",
    }
    allowed_statuses = {
        "no_explicit_memory_write", "explicit_memory_write", "unknown_effect",
        "unresolved_target", "indirect_call", "missing_callee_flow",
    }
    for record_index, fact in enumerate(records, 1):
        where = f"direct call memory effect record {record_index}"
        if (
            not isinstance(fact, dict)
            or set(fact) != expected_fields
            or fact.get("format") != DIRECT_CALL_MEMORY_EFFECT_FORMAT
        ):
            raise ValueError(f"{where}: unexpected format or fields")
        if any(not isinstance(fact.get(key), str) or not fact[key] for key in ("program_id", "function_entry", "address")):
            raise ValueError(f"{where}: invalid operation identity")
        time = _int(fact.get("time"), f"{where} operation time")
        opcode = fact.get("opcode")
        if opcode not in {"CALL", "CALLIND"}:
            raise ValueError(f"{where}: invalid call opcode")
        status = fact.get("status")
        if status not in allowed_statuses:
            raise ValueError(f"{where}: invalid status")
        callee_entry = fact.get("callee_entry")
        if callee_entry is not None and (not isinstance(callee_entry, str) or not callee_entry):
            raise ValueError(f"{where}: invalid callee entry")
        effect_opcodes = fact.get("effect_opcodes")
        if (
            not isinstance(effect_opcodes, list)
            or any(not isinstance(value, str) or not value for value in effect_opcodes)
            or len(effect_opcodes) != len(set(effect_opcodes))
            or effect_opcodes != sorted(effect_opcodes)
        ):
            raise ValueError(f"{where}: invalid effect opcode set")
        provenance = fact.get("provenance")
        if not isinstance(provenance, dict) or set(provenance) != expected_provenance:
            raise ValueError(f"{where}: invalid provenance")
        caller_sha = provenance.get("caller_pcode_flow_sha256")
        if not isinstance(caller_sha, str) or _SHA256.fullmatch(caller_sha) is None:
            raise ValueError(f"{where}: invalid caller P-code flow hash")
        _int(provenance.get("caller_pcode_flow_record_index"), f"{where} caller P-code flow row")
        callee_sha = provenance.get("callee_pcode_flow_sha256")
        if callee_sha is not None and (not isinstance(callee_sha, str) or _SHA256.fullmatch(callee_sha) is None):
            raise ValueError(f"{where}: invalid callee P-code flow hash")
        callee_count = _int(provenance.get("callee_pcode_flow_record_count"), f"{where} callee P-code flow row count")

        has_callee = callee_entry is not None
        has_callee_flow = callee_sha is not None and callee_count > 0
        if status == "no_explicit_memory_write":
            if opcode != "CALL" or not has_callee or not has_callee_flow or effect_opcodes:
                raise ValueError(f"{where}: write-free status lacks a complete resolved direct callee flow")
        elif status == "explicit_memory_write":
            if opcode != "CALL" or not has_callee_flow or "STORE" not in effect_opcodes:
                raise ValueError(f"{where}: explicit write status lacks a STORE witness")
        elif status == "unknown_effect":
            if opcode != "CALL" or not has_callee_flow or not effect_opcodes or "STORE" in effect_opcodes:
                raise ValueError(f"{where}: unknown status lacks an unmodeled-op witness")
        elif status == "missing_callee_flow":
            if opcode != "CALL" or not has_callee or callee_sha is not None or callee_count != 0 or effect_opcodes:
                raise ValueError(f"{where}: missing-flow status has inconsistent provenance")
        elif status == "unresolved_target":
            if opcode != "CALL" or has_callee or callee_sha is not None or callee_count != 0 or effect_opcodes:
                raise ValueError(f"{where}: unresolved-target status has inconsistent provenance")
        elif status == "indirect_call":
            if opcode != "CALLIND" or has_callee or callee_sha is not None or callee_count != 0 or effect_opcodes:
                raise ValueError(f"{where}: indirect-call status has inconsistent provenance")

        program_id = fact["program_id"]
        function_entry = fact["function_entry"]
        function_key = (program_id, function_entry)
        key = (program_id, function_entry, fact["address"], time)
        if key in indexed:
            raise ValueError(f"{where}: duplicate operation identity")
        cfg_item = cfg_by_function.get(function_key)
        if cfg_item is None:
            raise ValueError(f"{where}: missing CFG for program {program_id} function {function_entry}")
        cfg = cfg_item[1]
        operation_location = cfg["operations"].get((fact["address"], time))
        if operation_location is None or operation_location[2] != opcode:
            raise ValueError(f"{where}: operation does not match CFG call")
        indexed[key] = fact
        indices_by_function.setdefault(function_key, []).append(record_index)
    return indexed, indices_by_function


def _index_direct_call_memory_effect_closures(
    records: list[dict[str, Any]],
    cfg_by_function: dict[tuple[str, str], tuple[int, dict[str, Any]]],
) -> tuple[dict[tuple[str, str, str, int], dict[str, Any]], dict[tuple[str, str], list[int]]]:
    indexed: dict[tuple[str, str, str, int], dict[str, Any]] = {}
    indices_by_function: dict[tuple[str, str], list[int]] = {}
    expected_fields = {
        "format", "program_id", "function_entry", "address", "time", "opcode",
        "callee_entry", "status", "effect_opcodes", "provenance",
    }
    expected_provenance = {
        "caller_pcode_flow_sha256", "caller_pcode_flow_record_index",
        "callee_pcode_flow_sha256", "callee_pcode_flow_record_count",
        "closure_sha256", "closure_function_entries", "closure_call_site_count",
    }
    statuses = {
        "no_explicit_memory_write", "explicit_memory_write", "unknown_effect",
        "unresolved_target", "indirect_call", "missing_callee_flow",
    }
    for record_index, fact in enumerate(records, 1):
        where = f"direct call memory effect closure record {record_index}"
        if (
            not isinstance(fact, dict)
            or set(fact) != expected_fields
            or fact.get("format") != DIRECT_CALL_MEMORY_EFFECT_CLOSURE_FORMAT
        ):
            raise ValueError(f"{where}: unexpected format or fields")
        if any(not isinstance(fact.get(key), str) or not fact[key] for key in ("program_id", "function_entry", "address")):
            raise ValueError(f"{where}: invalid operation identity")
        time = _int(fact.get("time"), f"{where} operation time")
        opcode = fact.get("opcode")
        status = fact.get("status")
        if opcode not in {"CALL", "CALLIND"} or status not in statuses:
            raise ValueError(f"{where}: invalid call opcode or status")
        callee_entry = fact.get("callee_entry")
        if callee_entry is not None and (not isinstance(callee_entry, str) or not callee_entry):
            raise ValueError(f"{where}: invalid callee entry")
        effects = fact.get("effect_opcodes")
        if (
            not isinstance(effects, list)
            or any(not isinstance(value, str) or not value for value in effects)
            or len(effects) != len(set(effects))
            or effects != sorted(effects)
        ):
            raise ValueError(f"{where}: invalid effect opcode set")
        provenance = fact.get("provenance")
        if not isinstance(provenance, dict) or set(provenance) != expected_provenance:
            raise ValueError(f"{where}: invalid provenance")
        for field in ("caller_pcode_flow_sha256", "closure_sha256"):
            value = provenance[field]
            if value is not None and (not isinstance(value, str) or _SHA256.fullmatch(value) is None):
                raise ValueError(f"{where}: invalid {field}")
        if not isinstance(provenance["caller_pcode_flow_sha256"], str):
            raise ValueError(f"{where}: missing caller P-code flow hash")
        caller_row_index = _int(provenance["caller_pcode_flow_record_index"], f"{where} caller P-code flow row")
        if caller_row_index == 0:
            raise ValueError(f"{where}: caller P-code flow row must be positive")
        callee_sha = provenance["callee_pcode_flow_sha256"]
        if callee_sha is not None and (not isinstance(callee_sha, str) or _SHA256.fullmatch(callee_sha) is None):
            raise ValueError(f"{where}: invalid callee P-code flow hash")
        callee_count = _int(provenance["callee_pcode_flow_record_count"], f"{where} callee flow row count")
        closure_entries = provenance["closure_function_entries"]
        if (
            not isinstance(closure_entries, list)
            or any(not isinstance(entry, str) or not entry for entry in closure_entries)
            or len(closure_entries) != len(set(closure_entries))
            or closure_entries != sorted(closure_entries)
        ):
            raise ValueError(f"{where}: invalid closure function entries")
        closure_calls = _int(provenance["closure_call_site_count"], f"{where} closure call count")

        has_callee = isinstance(callee_entry, str)
        has_flow = callee_sha is not None and callee_count > 0
        has_no_flow = callee_sha is None and callee_count == 0
        if status == "no_explicit_memory_write":
            valid = opcode == "CALL" and has_callee and has_flow and bool(closure_entries) and callee_entry in closure_entries and not effects
        elif status == "explicit_memory_write":
            valid = opcode == "CALL" and has_callee and has_flow and bool(closure_entries) and callee_entry in closure_entries and "STORE" in effects
        elif status == "unknown_effect":
            valid = opcode == "CALL" and has_callee and has_flow and bool(closure_entries) and callee_entry in closure_entries and bool(effects) and "STORE" not in effects
        elif status == "missing_callee_flow":
            valid = opcode == "CALL" and has_callee and has_no_flow and not closure_entries and provenance["closure_sha256"] is None and not effects and closure_calls == 0
        elif status == "unresolved_target":
            valid = opcode == "CALL" and not has_callee and has_no_flow and not closure_entries and provenance["closure_sha256"] is None and not effects and closure_calls == 0
        else:
            valid = opcode == "CALLIND" and not has_callee and has_no_flow and not closure_entries and provenance["closure_sha256"] is None and not effects and closure_calls == 0
        if not valid or has_flow != bool(closure_entries) or has_flow != (provenance["closure_sha256"] is not None):
            raise ValueError(f"{where}: status and closure provenance disagree")

        function_key = (fact["program_id"], fact["function_entry"])
        key = (*function_key, fact["address"], time)
        if key in indexed:
            raise ValueError(f"{where}: duplicate operation identity")
        cfg_item = cfg_by_function.get(function_key)
        if cfg_item is None:
            raise ValueError(f"{where}: missing CFG for program {function_key[0]} function {function_key[1]}")
        operation = cfg_item[1]["operations"].get((fact["address"], time))
        if operation is None or operation[2] != opcode:
            raise ValueError(f"{where}: operation does not match CFG call")
        indexed[key] = fact
        indices_by_function.setdefault(function_key, []).append(record_index)
    return indexed, indices_by_function


def _memory_store_non_alias_reason(
    tracked: dict[str, Any], write: dict[str, Any], *,
    parameter_index: int, field_offset: int, field_width: int,
) -> str | None:
    tracked_physical = tracked["memory_physical_space"]
    write_physical = write["memory_physical_space"]
    if tracked_physical is not None and write_physical is not None and tracked_physical != write_physical:
        return "different_physical_space"
    if tracked["memory_space"] != write["memory_space"]:
        return None
    if tracked["location_status"] != "parameter_rooted_constant_offset":
        return None
    if write["location_status"] != "parameter_rooted_constant_offset":
        return None
    if tracked["root_parameter_index"] != parameter_index or write["root_parameter_index"] != parameter_index:
        return None
    if tracked["offset_bytes"] != field_offset or tracked["memory_width_bytes"] != field_width:
        return None
    geometry_fields = (
        "memory_pointer_width_bytes", "memory_space_size_bits", "memory_addressable_unit_bytes",
    )
    if any(tracked[field] is None or tracked[field] != write[field] for field in geometry_fields):
        return None
    modulus = (1 << tracked["memory_space_size_bits"]) * tracked["memory_addressable_unit_bytes"]
    pointer_modulus = 1 << (8 * tracked["memory_pointer_width_bytes"])
    write_width = write["memory_width_bytes"]
    if modulus != pointer_modulus or write_width is None or field_width >= modulus or write_width >= modulus:
        return None
    delta = (write["offset_bytes"] - field_offset) % modulus
    if delta >= field_width and modulus - delta >= write_width:
        return "same_root_disjoint_byte_ranges"
    return None


def _has_hazard(operations: list[dict[str, Any]], start: int, stop: int) -> bool:
    return any(operation["opcode"] in HAZARD_OPCODES for operation in operations[start:stop])


def _find_path(
    cfg: dict[str, Any],
    start: tuple[int, int, str],
    target: tuple[int, int, str],
    *,
    avoid_effects: bool,
    max_expansions: int,
) -> tuple[list[int] | None, int]:
    start_block, start_position, _ = start
    target_block, target_position, _ = target
    blocks = cfg["blocks"]
    start_operations = blocks[start_block]["operations"]
    if start_block == target_block and start_position < target_position:
        if avoid_effects and _has_hazard(start_operations, start_position + 1, target_position):
            return None, 0
        return [start_block], 0
    if avoid_effects and _has_hazard(start_operations, start_position + 1, len(start_operations)):
        return None, 0

    # Parent links keep reconstruction linear in the selected path rather than
    # copying a growing path list for every queued block.
    states: list[tuple[int, int]] = [(start_block, -1)]
    pending = deque()
    for successor in sorted(blocks[start_block]["successors"]):
        states.append((successor, 0))
        pending.append(len(states) - 1)
    visited: set[int] = set()
    expansions = 0
    while pending:
        state_index = pending.popleft()
        block_index, _ = states[state_index]
        block = blocks[block_index]
        operations = block["operations"]
        if block_index == target_block:
            if not avoid_effects or not _has_hazard(operations, 0, target_position):
                path = []
                cursor = state_index
                while cursor >= 0:
                    path.append(states[cursor][0])
                    cursor = states[cursor][1]
                return list(reversed(path)), expansions
            continue
        if block_index in visited:
            continue
        if expansions >= max_expansions:
            raise ValueError(f"CFG path search budget exceeded: {max_expansions}")
        expansions += 1
        visited.add(block_index)
        if avoid_effects and _has_hazard(operations, 0, len(operations)):
            continue
        for successor in sorted(block["successors"]):
            states.append((successor, state_index))
            pending.append(len(states) - 1)
    return None, expansions


def audit_field_store_load_paths(
    pair_graphs: list[dict[str, Any]],
    cfg_records: list[dict[str, Any]],
    *,
    pair_graph_sha256: str,
    cfg_sha256: str,
    max_pairs: int = 100_000,
    max_path_expansions: int = 1_000_000,
) -> list[dict[str, Any]]:
    """Find CFG paths without explicit STORE/CALL effects between paired accesses.

    A candidate path is not proof of memory reaching-definition: branch
    feasibility and writes hidden behind unmodeled effects are not evaluated.
    """
    if any(not isinstance(value, str) or _SHA256.fullmatch(value) is None for value in (pair_graph_sha256, cfg_sha256)):
        raise ValueError("input SHA-256 must be lowercase hexadecimal")
    if max_pairs < 1:
        raise ValueError("max_pairs must be positive")
    if max_path_expansions < 1:
        raise ValueError("max_path_expansions must be positive")
    cfg_by_function = _index_cfg(cfg_records)
    output = []
    seen_pairs: set[str] = set()
    path_expansions = 0
    for pair_index, graph in enumerate(pair_graphs, 1):
        identity = _pair_identity(graph, pair_index)
        if graph["graph_id"] in seen_pairs:
            raise ValueError(f"duplicate field-access pair: {graph['graph_id']}")
        seen_pairs.add(graph["graph_id"])
        if len(output) >= max_pairs:
            raise ValueError(f"field store/load audit budget exceeded: {max_pairs}")
        function_entry = identity["function_entry"]
        program_id = identity["program_id"]
        cfg_item = cfg_by_function.get((program_id, function_entry))
        if cfg_item is None:
            raise ValueError(
                f"field-access pair {pair_index}: missing CFG for program {program_id} function {function_entry}"
            )
        cfg_record_index, cfg = cfg_item
        path_expansions_before = path_expansions
        store_location = None
        load_location = None
        if identity["store_time"] is not None:
            store_location = cfg["operations"].get((identity["store_address"], identity["store_time"]))
        if identity["load_time"] is not None:
            load_location = cfg["operations"].get((identity["load_address"], identity["load_time"]))

        if store_location is not None and store_location[2] != "STORE":
            raise ValueError(f"field-access pair {pair_index}: store row does not match CFG opcode")
        if load_location is not None and load_location[2] != "LOAD":
            raise ValueError(f"field-access pair {pair_index}: load row does not match CFG opcode")
        path: list[int] = []
        if store_location is None or load_location is None:
            status = "event_not_located"
        else:
            remaining = max_path_expansions - path_expansions
            safe_path, used = _find_path(
                cfg, store_location, load_location, avoid_effects=True, max_expansions=remaining,
            )
            path_expansions += used
            path = safe_path or []
            if path:
                status = "candidate_path_compatible"
            else:
                remaining = max_path_expansions - path_expansions
                any_path, used = _find_path(
                    cfg, store_location, load_location, avoid_effects=False, max_expansions=remaining,
                )
                path_expansions += used
                if any_path is None:
                    status = "no_cfg_path"
                else:
                    status = "intervening_store_or_call"
                    path = any_path
        output.append({
            "format": FORMAT,
            "program_id": identity["program_id"],
            "function_entry": function_entry,
            "parameter_index": identity["parameter_index"],
            "field_offset": (
                f"-0x{abs(identity['field_offset']):x}"
                if identity["field_offset"] < 0 else f"0x{identity['field_offset']:x}"
            ),
            "source_parameter_index": identity["source_parameter_index"],
            "status": status,
            "store": {
                "address": identity["store_address"],
                "time": identity["store_time"],
                "block_index": None if store_location is None else store_location[0],
            },
            "load": {
                "address": identity["load_address"],
                "time": identity["load_time"],
                "block_index": None if load_location is None else load_location[0],
            },
            "path_block_indices": path,
            "provenance": {
                "pair_graph_sha256": pair_graph_sha256,
                "pair_graph_record_index": pair_index,
                "cfg_sha256": cfg_sha256,
                "cfg_record_index": cfg_record_index,
                "path_expansion_cap": max_path_expansions,
                "path_expansions_before": path_expansions_before,
                "path_expansions_used": path_expansions - path_expansions_before,
                "store_source_id": identity["store_source_id"],
                "load_source_id": identity["load_source_id"],
            },
        })
    return output


def _route_blocks(
    parents: dict[tuple[int, int, bool], tuple[int, int, bool] | None],
    state: tuple[int, int, bool],
    blocks: dict[int, dict[str, Any]],
) -> list[int]:
    route = []
    cursor: tuple[int, int, bool] | None = state
    while cursor is not None:
        route.append(cursor)
        cursor = parents[cursor]
    route.reverse()
    result: list[int] = []
    for index, (block_index, position, _effect_seen) in enumerate(route):
        if index == 0:
            result.append(block_index)
            continue
        previous_block, previous_position, _ = route[index - 1]
        previous_size = len(blocks[previous_block]["operations"])
        if block_index != previous_block or (position == 0 and previous_position == previous_size):
            result.append(block_index)
    return result


def _may_write_tracked_space(
    operation: dict[str, Any], tracked_space: str, *,
    tracked_physical_space: str | None = None, physical_space_aware: bool = False,
    access_facts_enabled: bool = False,
    non_alias_store_locations: set[tuple[str, int]] | None = None,
    non_effect_call_locations: set[tuple[str, int]] | None = None,
    indirect_effect_sources: dict[tuple[str, int], dict[str, Any]] | None = None,
) -> bool:
    """Keep possible effects in the tracked P-code space or with unknown space."""
    opcode = operation["opcode"]
    if opcode == "INDIRECT":
        link = operation.get("indirect_effect_link")
        if not isinstance(link, dict) or link.get("status") != "resolved" or link.get("source_opcode") == "INDIRECT":
            return True
        source = None if indirect_effect_sources is None else indirect_effect_sources.get(
            (link.get("source_address"), link.get("source_time")),
        )
        if source is None or source.get("opcode") != link.get("source_opcode"):
            return True
        return _may_write_tracked_space(
            source, tracked_space,
            tracked_physical_space=tracked_physical_space,
            physical_space_aware=physical_space_aware,
            access_facts_enabled=access_facts_enabled,
            non_alias_store_locations=non_alias_store_locations,
            non_effect_call_locations=non_effect_call_locations,
            indirect_effect_sources=indirect_effect_sources,
        )
    if opcode == "STORE":
        if access_facts_enabled:
            location = (operation["address"], operation["time"])
            return non_alias_store_locations is None or location not in non_alias_store_locations
        if physical_space_aware:
            write_space = operation.get("memory_physical_space")
            return not write_space or not tracked_physical_space or write_space == tracked_physical_space
        write_space = operation.get("memory_space")
        return not write_space or write_space == tracked_space
    if opcode == "CALL" and non_effect_call_locations is not None:
        if (operation["address"], operation["time"]) in non_effect_call_locations:
            return False
    return opcode not in NO_EXPLICIT_MEMORY_WRITE_OPCODES


def _find_routes(
    cfg: dict[str, Any],
    start: tuple[int, int],
    target: tuple[int, int],
    *,
    stop_at: tuple[int, int] | None = None,
    classify_effects: bool = False,
    tracked_memory_space: str | None = None,
    tracked_physical_space: str | None = None,
    physical_space_aware: bool = False,
    access_facts_enabled: bool = False,
    non_alias_store_locations: set[tuple[str, int]] | None = None,
    non_effect_call_locations: set[tuple[str, int]] | None = None,
    indirect_effect_sources: dict[tuple[str, int], dict[str, Any]] | None = None,
    max_expansions: int,
) -> tuple[list[int] | None, list[int] | None, int]:
    """Find one clean and, optionally, one effect-bearing CFG witness."""
    start_state = (start[0], start[1], False)
    pending = deque([start_state])
    parents: dict[tuple[int, int, bool], tuple[int, int, bool] | None] = {start_state: None}
    clean_path: list[int] | None = None
    effect_path: list[int] | None = None
    expansions = 0
    blocks = cfg["blocks"]
    while pending:
        state = pending.popleft()
        block_index, position, effect_seen = state
        if (block_index, position) == target:
            witness = _route_blocks(parents, state, blocks)
            if effect_seen:
                if effect_path is None:
                    effect_path = witness
            elif clean_path is None:
                clean_path = witness
            if not classify_effects or (clean_path is not None and effect_path is not None):
                return clean_path, effect_path, expansions
            continue
        if stop_at == (block_index, position):
            continue
        if expansions >= max_expansions:
            raise ValueError(f"CFG path search budget exceeded: {max_expansions}")
        expansions += 1
        operations = blocks[block_index]["operations"]
        if position < len(operations):
            operation = operations[position]
            next_effect = effect_seen
            if classify_effects:
                next_effect = next_effect or (
                    True if tracked_memory_space is None
                    else _may_write_tracked_space(
                        operation, tracked_memory_space,
                        tracked_physical_space=tracked_physical_space,
                        physical_space_aware=physical_space_aware,
                        access_facts_enabled=access_facts_enabled,
                        non_alias_store_locations=non_alias_store_locations,
                        non_effect_call_locations=non_effect_call_locations,
                        indirect_effect_sources=indirect_effect_sources,
                    )
                )
            next_states = [(block_index, position + 1, bool(next_effect))]
        else:
            next_states = [(successor, 0, effect_seen) for successor in sorted(blocks[block_index]["successors"])]
        for next_state in next_states:
            if next_state not in parents:
                parents[next_state] = state
                pending.append(next_state)
    return clean_path, effect_path, expansions


def _index_interprocedural_memory_effects(
    records: list[dict[str, Any]],
    cfg_by_function: dict[tuple[str, str], tuple[int, dict[str, Any]]],
) -> tuple[
    dict[tuple[str, str, str, str, int], dict[str, Any]],
    dict[tuple[str, str, str], list[int]],
]:
    indexed: dict[tuple[str, str, str, str, int], dict[str, Any]] = {}
    indices_by_pair: dict[tuple[str, str, str], list[int]] = {}
    expected_fields = {
        "format", "program_id", "function_entry", "field_pair_id", "address", "time",
        "opcode", "callee_entry", "status", "effect_opcodes", "aliasing_store_record_indices",
        "non_aliasing_store_record_indices", "provenance",
    }
    provenance_fields = {
        "field_access_pair_graph_sha256", "field_access_pair_graph_record_index", "cfg_sha256",
        "memory_store_access_sha256", "memory_store_access_record_indices",
        "tracked_memory_store_access_record_index", "caller_parameter_roots_sha256",
        "caller_parameter_root_record_indices", "caller_pcode_flow_sha256",
        "caller_pcode_flow_record_index", "pcode_flow_manifest_sha256", "closure_sha256",
        "closure_function_entries", "unknown_operation_ids", "memory_access_comparisons",
    }
    provenance_v2_fields = provenance_fields | {"indirect_effect_link_cfg_record_indices"}
    hash_fields = {
        "field_access_pair_graph_sha256", "cfg_sha256", "memory_store_access_sha256",
        "caller_parameter_roots_sha256", "caller_pcode_flow_sha256", "pcode_flow_manifest_sha256",
    }
    statuses = {
        "no_aliasing_memory_effect", "possible_aliasing_write", "unknown_effect",
        "missing_callee_flow", "unresolved_target", "indirect_call",
    }

    def indices(value: Any, where: str) -> list[int]:
        if not isinstance(value, list):
            raise ValueError(f"{where}: expected record-index list")
        parsed = [_int(item, where) for item in value]
        if any(item == 0 for item in parsed) or parsed != sorted(set(parsed)):
            raise ValueError(f"{where}: indices must be positive, unique, and sorted")
        return parsed

    for record_index, fact in enumerate(records, 1):
        where = f"interprocedural memory effect record {record_index}"
        fact_format = fact.get("format") if isinstance(fact, dict) else None
        expected_provenance = (
            provenance_v2_fields if fact_format == INTERPROCEDURAL_MEMORY_EFFECT_FORMAT_V2
            else provenance_fields
        )
        if (
            not isinstance(fact, dict)
            or set(fact) != expected_fields
            or fact_format not in {
                INTERPROCEDURAL_MEMORY_EFFECT_FORMAT, INTERPROCEDURAL_MEMORY_EFFECT_FORMAT_V2,
            }
        ):
            raise ValueError(f"{where}: unexpected format or fields")
        for key in ("program_id", "function_entry", "field_pair_id", "address"):
            if not isinstance(fact.get(key), str) or not fact[key]:
                raise ValueError(f"{where}: invalid {key}")
        time = _int(fact.get("time"), f"{where} operation time")
        opcode = fact.get("opcode")
        status = fact.get("status")
        callee_entry = fact.get("callee_entry")
        if opcode not in {"CALL", "CALLIND"} or status not in statuses:
            raise ValueError(f"{where}: invalid opcode or status")
        if callee_entry is not None and (not isinstance(callee_entry, str) or not callee_entry):
            raise ValueError(f"{where}: invalid callee entry")
        effects = fact.get("effect_opcodes")
        if (
            not isinstance(effects, list)
            or any(not isinstance(item, str) or not item for item in effects)
            or effects != sorted(set(effects))
        ):
            raise ValueError(f"{where}: invalid effect opcode list")
        aliasing = indices(fact.get("aliasing_store_record_indices"), f"{where} aliasing stores")
        non_aliasing = indices(fact.get("non_aliasing_store_record_indices"), f"{where} non-aliasing stores")
        if set(aliasing) & set(non_aliasing):
            raise ValueError(f"{where}: a store cannot be both aliasing and non-aliasing")
        provenance = fact.get("provenance")
        if not isinstance(provenance, dict) or set(provenance) != expected_provenance:
            raise ValueError(f"{where}: invalid provenance fields")
        for field in hash_fields:
            if not isinstance(provenance[field], str) or _SHA256.fullmatch(provenance[field]) is None:
                raise ValueError(f"{where}: invalid {field}")
        closure_sha = provenance["closure_sha256"]
        if closure_sha is not None and (not isinstance(closure_sha, str) or _SHA256.fullmatch(closure_sha) is None):
            raise ValueError(f"{where}: invalid closure SHA-256")
        pair_row = _int(provenance["field_access_pair_graph_record_index"], f"{where} pair row")
        caller_row = _int(provenance["caller_pcode_flow_record_index"], f"{where} caller P-code row")
        tracked_index = _int(provenance["tracked_memory_store_access_record_index"], f"{where} tracked memory row")
        comparisons = _int(provenance["memory_access_comparisons"], f"{where} memory comparisons")
        if pair_row == 0 or caller_row == 0 or tracked_index == 0:
            raise ValueError(f"{where}: provenance indices must be positive")
        memory_indices = indices(provenance["memory_store_access_record_indices"], f"{where} memory stores")
        indices(provenance["caller_parameter_root_record_indices"], f"{where} parameter roots")
        closure_entries = provenance["closure_function_entries"]
        if (
            not isinstance(closure_entries, list)
            or any(not isinstance(entry, str) or not entry for entry in closure_entries)
            or closure_entries != sorted(set(closure_entries))
        ):
            raise ValueError(f"{where}: invalid closure function entries")
        if fact_format == INTERPROCEDURAL_MEMORY_EFFECT_FORMAT_V2:
            link_cfg_indices = indices(
                provenance["indirect_effect_link_cfg_record_indices"],
                f"{where} INDIRECT link CFG records",
            )
            expected_link_cfg_indices = sorted({
                cfg_by_function[(fact["program_id"], entry)][0]
                for entry in [fact["function_entry"], *closure_entries]
                if (fact["program_id"], entry) in cfg_by_function
                and cfg_by_function[(fact["program_id"], entry)][1]["format"] == CFG_FORMAT_V4
            })
            if link_cfg_indices != expected_link_cfg_indices:
                raise ValueError(f"{where}: INDIRECT link CFG provenance does not match the closure")
        unknown_ids = provenance["unknown_operation_ids"]
        if (
            not isinstance(unknown_ids, list)
            or any(not isinstance(value, str) or not value for value in unknown_ids)
            or unknown_ids != sorted(set(unknown_ids))
        ):
            raise ValueError(f"{where}: invalid unknown operation identities")
        if not set(aliasing + non_aliasing) <= set(memory_indices):
            raise ValueError(f"{where}: store classifications reference an unpinned memory row")
        has_closure = bool(closure_entries)
        if has_closure != (closure_sha is not None):
            raise ValueError(f"{where}: closure rows and digest disagree")
        if has_closure:
            if set(aliasing + non_aliasing) != set(memory_indices) or comparisons != len(memory_indices):
                raise ValueError(f"{where}: closure STORE facts are not fully classified")
        elif memory_indices or aliasing or non_aliasing or comparisons:
            raise ValueError(f"{where}: incomplete closure claims STORE evidence")
        if not has_closure and provenance["caller_parameter_root_record_indices"]:
            raise ValueError(f"{where}: incomplete closure claims parameter-root evidence")
        if status == "no_aliasing_memory_effect":
            valid = (
                opcode == "CALL" and callee_entry in closure_entries and not aliasing
                and not unknown_ids and set(non_aliasing) == set(memory_indices)
            )
        elif status == "possible_aliasing_write":
            valid = opcode == "CALL" and callee_entry in closure_entries and bool(aliasing) and not unknown_ids
        elif status == "unknown_effect":
            valid = opcode == "CALL" and callee_entry in closure_entries and bool(unknown_ids)
        elif status == "missing_callee_flow":
            valid = opcode == "CALL" and isinstance(callee_entry, str) and not closure_entries and bool(unknown_ids)
        elif status == "unresolved_target":
            valid = opcode == "CALL" and callee_entry is None and not closure_entries and bool(unknown_ids)
        else:
            valid = opcode == "CALLIND" and callee_entry is None and not closure_entries and bool(unknown_ids)
        if not valid:
            raise ValueError(f"{where}: status and evidence disagree")

        function_key = (fact["program_id"], fact["function_entry"])
        cfg_item = cfg_by_function.get(function_key)
        if cfg_item is None:
            raise ValueError(f"{where}: missing CFG for caller function")
        operation = cfg_item[1]["operations"].get((fact["address"], time))
        if operation is None or operation[2] != opcode:
            raise ValueError(f"{where}: operation does not match CFG call")
        key = (*function_key, fact["field_pair_id"], fact["address"], time)
        if key in indexed:
            raise ValueError(f"{where}: duplicate pair/call identity")
        indexed[key] = fact
        indices_by_pair.setdefault((*function_key, fact["field_pair_id"]), []).append(record_index)
    return indexed, indices_by_pair


def audit_field_store_load_dominance(
    pair_graphs: list[dict[str, Any]],
    cfg_records: list[dict[str, Any]],
    *,
    pair_graph_sha256: str,
    cfg_sha256: str,
    memory_store_access_rows: list[dict[str, Any]] | None = None,
    memory_store_access_sha256: str | None = None,
    direct_call_memory_effect_rows: list[dict[str, Any]] | None = None,
    direct_call_memory_effect_sha256: str | None = None,
    direct_call_memory_effect_closure_rows: list[dict[str, Any]] | None = None,
    direct_call_memory_effect_closure_sha256: str | None = None,
    interprocedural_memory_effect_rows: list[dict[str, Any]] | None = None,
    interprocedural_memory_effect_sha256: str | None = None,
    max_pairs: int = 100_000,
    max_path_expansions: int = 1_000_000,
    max_memory_access_comparisons: int = 1_000_000,
) -> list[dict[str, Any]]:
    """Require a candidate store to dominate a paired load with no memory-effect path.

    A store in a known different P-code address space is outside the tracked
    space. Same-space and unknown-space stores, calls, indirect effects, and
    unclassified P-code opcodes remain possible effects. A positive row is a
    structural candidate, not a runtime or semantic value-flow claim.
    """
    if any(not isinstance(value, str) or _SHA256.fullmatch(value) is None for value in (pair_graph_sha256, cfg_sha256)):
        raise ValueError("input SHA-256 must be lowercase hexadecimal")
    if max_pairs < 1:
        raise ValueError("max_pairs must be positive")
    if max_path_expansions < 1:
        raise ValueError("max_path_expansions must be positive")
    if max_memory_access_comparisons < 1:
        raise ValueError("max_memory_access_comparisons must be positive")
    access_facts_enabled = memory_store_access_rows is not None
    direct_call_effects_enabled = direct_call_memory_effect_rows is not None
    call_effect_closures_enabled = direct_call_memory_effect_closure_rows is not None
    interprocedural_effects_enabled = interprocedural_memory_effect_rows is not None
    if sum((direct_call_effects_enabled, call_effect_closures_enabled, interprocedural_effects_enabled)) > 1:
        raise ValueError("direct-call, transitive-closure, and interprocedural sidecars are mutually exclusive")
    call_effects_enabled = direct_call_effects_enabled or call_effect_closures_enabled or interprocedural_effects_enabled
    if access_facts_enabled:
        if not isinstance(memory_store_access_sha256, str) or _SHA256.fullmatch(memory_store_access_sha256) is None:
            raise ValueError("memory store access SHA-256 must be lowercase hexadecimal")
    elif memory_store_access_sha256 is not None:
        raise ValueError("memory store access SHA-256 requires memory store access rows")
    if call_effects_enabled:
        if not access_facts_enabled:
            raise ValueError("direct call memory effects require memory store access rows")
    interprocedural_effect_by_operation = {}
    interprocedural_effect_indices_by_pair = {}
    if direct_call_effects_enabled:
        if not isinstance(direct_call_memory_effect_sha256, str) or _SHA256.fullmatch(direct_call_memory_effect_sha256) is None:
            raise ValueError("direct call memory effect SHA-256 must be lowercase hexadecimal")
    elif direct_call_memory_effect_sha256 is not None:
        raise ValueError("direct call memory effect SHA-256 requires direct call memory effect rows")
    if call_effect_closures_enabled:
        if not isinstance(direct_call_memory_effect_closure_sha256, str) or _SHA256.fullmatch(direct_call_memory_effect_closure_sha256) is None:
            raise ValueError("direct call memory effect closure SHA-256 must be lowercase hexadecimal")
    elif direct_call_memory_effect_closure_sha256 is not None:
        raise ValueError("direct call memory effect closure SHA-256 requires closure rows")
    if interprocedural_effects_enabled:
        if not isinstance(interprocedural_memory_effect_sha256, str) or _SHA256.fullmatch(interprocedural_memory_effect_sha256) is None:
            raise ValueError("interprocedural memory effect SHA-256 must be lowercase hexadecimal")
    elif interprocedural_memory_effect_sha256 is not None:
        raise ValueError("interprocedural memory effect SHA-256 requires interprocedural rows")
    cfg_by_function = _index_cfg(cfg_records)
    indirect_effect_links_enabled = any(
        cfg["format"] == CFG_FORMAT_V4 for _, cfg in cfg_by_function.values()
    )
    if access_facts_enabled:
        memory_access_by_operation, memory_access_indices_by_function, memory_access_record_indices = (
            _index_memory_store_accesses(memory_store_access_rows, cfg_by_function)
        )
    else:
        memory_access_by_operation = {}
        memory_access_indices_by_function = {}
        memory_access_record_indices = {}
    if direct_call_effects_enabled:
        call_effect_by_operation, call_effect_indices_by_function = _index_direct_call_memory_effects(
            direct_call_memory_effect_rows, cfg_by_function,
        )
    elif call_effect_closures_enabled:
        call_effect_by_operation, call_effect_indices_by_function = _index_direct_call_memory_effect_closures(
            direct_call_memory_effect_closure_rows, cfg_by_function,
        )
    elif interprocedural_effects_enabled:
        interprocedural_effect_by_operation, interprocedural_effect_indices_by_pair = (
            _index_interprocedural_memory_effects(interprocedural_memory_effect_rows, cfg_by_function)
        )
        pair_rows = {}
        for pair_index, graph in enumerate(pair_graphs, 1):
            identity = _pair_identity(graph, pair_index)
            pair_key = (identity["program_id"], identity["function_entry"], graph["graph_id"])
            pair_rows[pair_key] = (pair_index, identity)
        for pair_key, record_indices in interprocedural_effect_indices_by_pair.items():
            pair_row = pair_rows.get(pair_key)
            if pair_row is None:
                raise ValueError("interprocedural sidecar references an unknown field-access pair")
            pair_index, identity = pair_row
            tracked_key = (
                identity["program_id"], identity["function_entry"],
                identity["store_address"], identity["store_time"],
            )
            tracked_access_index = memory_access_record_indices.get(tracked_key)
            for effect_index in record_indices:
                fact = interprocedural_memory_effect_rows[effect_index - 1]
                provenance = fact["provenance"]
                if (
                    provenance["field_access_pair_graph_sha256"] != pair_graph_sha256
                    or provenance["field_access_pair_graph_record_index"] != pair_index
                    or provenance["tracked_memory_store_access_record_index"] != tracked_access_index
                ):
                    raise ValueError(f"interprocedural memory effect record {effect_index}: pair provenance mismatch")
                for memory_index in provenance["memory_store_access_record_indices"]:
                    if memory_index > len(memory_store_access_rows):
                        raise ValueError(f"interprocedural memory effect record {effect_index}: memory row index is out of range")
                    memory_fact = memory_store_access_rows[memory_index - 1]
                    if (
                        memory_fact["program_id"] != fact["program_id"]
                        or memory_fact["function_entry"] not in provenance["closure_function_entries"]
                    ):
                        raise ValueError(f"interprocedural memory effect record {effect_index}: closure store identity mismatch")
        call_effect_by_operation, call_effect_indices_by_function = {}, {}
    else:
        call_effect_by_operation = {}
        call_effect_indices_by_function = {}
    output = []
    seen_pairs: set[str] = set()
    path_expansions = 0
    memory_access_comparisons = 0
    for pair_index, graph in enumerate(pair_graphs, 1):
        identity = _pair_identity(graph, pair_index)
        if graph["graph_id"] in seen_pairs:
            raise ValueError(f"duplicate field-access pair: {graph['graph_id']}")
        seen_pairs.add(graph["graph_id"])
        if len(output) >= max_pairs:
            raise ValueError(f"field store/load audit budget exceeded: {max_pairs}")
        cfg_item = cfg_by_function.get((identity["program_id"], identity["function_entry"]))
        if cfg_item is None:
            raise ValueError(
                f"field-access pair {pair_index}: missing CFG for program {identity['program_id']} "
                f"function {identity['function_entry']}"
            )
        cfg_record_index, cfg = cfg_item
        before = path_expansions
        memory_comparisons_before = memory_access_comparisons
        store_location = None if identity["store_time"] is None else cfg["operations"].get(
            (identity["store_address"], identity["store_time"])
        )
        load_location = None if identity["load_time"] is None else cfg["operations"].get(
            (identity["load_address"], identity["load_time"])
        )
        if store_location is not None and store_location[2] != "STORE":
            raise ValueError(f"field-access pair {pair_index}: store row does not match CFG opcode")
        if load_location is not None and load_location[2] != "LOAD":
            raise ValueError(f"field-access pair {pair_index}: load row does not match CFG opcode")

        store_detail = None if store_location is None else cfg["operation_details"][(identity["store_address"], identity["store_time"])]
        load_detail = None if load_location is None else cfg["operation_details"][(identity["load_address"], identity["load_time"])]
        store_memory_space = None if store_detail is None else store_detail.get("memory_space")
        load_memory_space = None if load_detail is None else load_detail.get("memory_space")
        store_width = None if store_detail is None else store_detail.get("memory_width_bytes")
        load_width = None if load_detail is None else load_detail.get("memory_width_bytes")
        memory_access_indices = memory_access_indices_by_function.get(
            (identity["program_id"], identity["function_entry"]), []
        )
        if interprocedural_effects_enabled:
            pair_key = (identity["program_id"], identity["function_entry"], graph["graph_id"])
            call_effect_indices = interprocedural_effect_indices_by_pair.get(pair_key, [])
            tracked_key = (
                identity["program_id"], identity["function_entry"],
                identity["store_address"], identity["store_time"],
            )
            tracked_access_index = memory_access_record_indices.get(tracked_key)
            for effect_index in call_effect_indices:
                fact = interprocedural_memory_effect_rows[effect_index - 1]
                provenance = fact["provenance"]
                if (
                    provenance["field_access_pair_graph_sha256"] != pair_graph_sha256
                    or provenance["field_access_pair_graph_record_index"] != pair_index
                    or provenance["cfg_sha256"] != cfg_sha256
                    or provenance["memory_store_access_sha256"] != memory_store_access_sha256
                    or provenance["tracked_memory_store_access_record_index"] != tracked_access_index
                ):
                    raise ValueError(f"field-access pair {pair_index}: interprocedural sidecar provenance mismatch")
            no_effect_call_locations = {
                (address, operation_time)
                for (program_id, function_entry, pair_id, address, operation_time), fact
                in interprocedural_effect_by_operation.items()
                if (program_id, function_entry, pair_id) == pair_key
                and fact["status"] == "no_aliasing_memory_effect"
            }
        else:
            call_effect_indices = call_effect_indices_by_function.get(
                (identity["program_id"], identity["function_entry"]), []
            )
            no_effect_call_locations = {
                (address, operation_time)
                for (program_id, function_entry, address, operation_time), fact in call_effect_by_operation.items()
                if (program_id, function_entry) == (identity["program_id"], identity["function_entry"])
                and fact["status"] == "no_explicit_memory_write"
            }
        non_alias_store_locations: set[tuple[str, int]] = set()
        candidate_access_fact = None
        candidate_access_complete = not access_facts_enabled
        if access_facts_enabled and store_location is not None and identity["store_time"] is not None:
            candidate_access_fact = memory_access_by_operation.get((
                identity["program_id"], identity["function_entry"],
                identity["store_address"], identity["store_time"],
            ))
            if candidate_access_fact is not None and candidate_access_fact["location_status"] == "parameter_rooted_constant_offset":
                if (
                    candidate_access_fact["root_parameter_index"] != identity["parameter_index"]
                    or candidate_access_fact["offset_bytes"] != identity["field_offset"]
                ):
                    raise ValueError(f"field-access pair {pair_index}: memory fact disagrees with paired store root or offset")
                if candidate_access_fact["memory_width_bytes"] != store_width:
                    raise ValueError(f"field-access pair {pair_index}: memory fact disagrees with paired store width")
                if cfg["format"] in {CFG_FORMAT_V3, CFG_FORMAT_V4} and load_detail is not None and (
                    candidate_access_fact["memory_physical_space"] != load_detail["memory_physical_space"]
                    or candidate_access_fact["memory_pointer_width_bytes"] != load_detail["memory_pointer_width_bytes"]
                ):
                    raise ValueError(f"field-access pair {pair_index}: paired accesses disagree on CFG/3 space metadata")
                candidate_access_complete = True
                for (address, operation_time), operation_location in cfg["operations"].items():
                    if operation_location[2] != "STORE" or (address, operation_time) == (
                        identity["store_address"], identity["store_time"],
                    ):
                        continue
                    memory_access_comparisons += 1
                    if memory_access_comparisons > max_memory_access_comparisons:
                        raise ValueError(
                            f"memory access comparison budget exceeded: {max_memory_access_comparisons}"
                        )
                    write_fact = memory_access_by_operation.get((
                        identity["program_id"], identity["function_entry"], address, operation_time,
                    ))
                    if write_fact is not None and _memory_store_non_alias_reason(
                        candidate_access_fact, write_fact,
                        parameter_index=identity["parameter_index"],
                        field_offset=identity["field_offset"],
                        field_width=store_width if isinstance(store_width, int) else 0,
                    ) is not None:
                        non_alias_store_locations.add((address, operation_time))
        entry_index = cfg["entry_block_index"]
        entry_to_store = None
        bypass_store = None
        clean_after_store = None
        effect_after_store = None
        store_reachable = None
        store_dominates = None
        if cfg["format"] not in {CFG_FORMAT_V2, CFG_FORMAT_V3, CFG_FORMAT_V4} or store_location is None or load_location is None:
            status = "incomplete_evidence"
        elif any(value is None for value in (store_memory_space, load_memory_space, store_width, load_width)):
            status = "incomplete_evidence"
        elif store_memory_space != load_memory_space or store_width != load_width:
            status = "access_shape_mismatch"
        elif access_facts_enabled and not candidate_access_complete:
            status = "incomplete_evidence"
        else:
            budget = max_path_expansions - path_expansions
            entry_to_store, _unused, used = _find_routes(
                cfg, (entry_index, 0), store_location[:2], max_expansions=budget,
            )
            path_expansions += used
            store_reachable = entry_to_store is not None
            if not store_reachable:
                status = "store_not_reachable"
            else:
                budget = max_path_expansions - path_expansions
                bypass_store, _unused, used = _find_routes(
                    cfg, (entry_index, 0), load_location[:2], stop_at=store_location[:2],
                    max_expansions=budget,
                )
                path_expansions += used
                store_dominates = bypass_store is None
                budget = max_path_expansions - path_expansions
                clean_after_store, effect_after_store, used = _find_routes(
                    cfg, (store_location[0], store_location[1] + 1), load_location[:2],
                    classify_effects=True, tracked_memory_space=store_memory_space,
                    tracked_physical_space=(
                        store_detail.get("memory_physical_space")
                        if cfg["format"] in {CFG_FORMAT_V3, CFG_FORMAT_V4} else None
                    ),
                    physical_space_aware=cfg["format"] in {CFG_FORMAT_V3, CFG_FORMAT_V4},
                    access_facts_enabled=access_facts_enabled,
                    non_alias_store_locations=non_alias_store_locations,
                    non_effect_call_locations=no_effect_call_locations,
                    indirect_effect_sources=cfg["operation_details"],
                    max_expansions=budget,
                )
                path_expansions += used
                if not store_dominates:
                    status = "store_not_dominating_load"
                elif effect_after_store is not None:
                    status = "possible_intervening_memory_effect"
                elif clean_after_store is None:
                    status = "no_post_store_cfg_path"
                else:
                    status = "unique_cfg_store_candidate"

        def access(
            location: tuple[int, int, str] | None,
            detail: dict[str, Any] | None,
            source_id: str,
            address: str,
            operation_time: int | None,
        ) -> dict[str, Any]:
            return {
                "source_id": source_id,
                "address": address,
                "time": operation_time,
                "block_index": None if location is None else location[0],
                "memory_space": None if detail is None else detail.get("memory_space"),
                "width_bytes": None if detail is None else detail.get("memory_width_bytes"),
            }

        result = {
            "format": (
                REACHING_FORMAT_V6 if indirect_effect_links_enabled
                else REACHING_FORMAT_V5 if interprocedural_effects_enabled
                else REACHING_FORMAT_V4 if call_effect_closures_enabled
                else REACHING_FORMAT_V3 if direct_call_effects_enabled
                else REACHING_FORMAT_V2 if access_facts_enabled else REACHING_FORMAT
            ),
            "program_id": identity["program_id"],
            "function_entry": identity["function_entry"],
            "parameter_index": identity["parameter_index"],
            "field_offset": (
                f"-0x{abs(identity['field_offset']):x}"
                if identity["field_offset"] < 0 else f"0x{identity['field_offset']:x}"
            ),
            "source_parameter_index": identity["source_parameter_index"],
            "status": status,
            "store": access(store_location, store_detail, identity["store_source_id"], identity["store_address"], identity["store_time"]),
            "load": access(load_location, load_detail, identity["load_source_id"], identity["load_address"], identity["load_time"]),
            "store_reachable_from_entry": store_reachable,
            "store_dominates_load": store_dominates,
            "clean_store_to_load_path_exists": clean_after_store is not None,
            "memory_effect_path_exists": effect_after_store is not None,
            "witnesses": {
                "entry_to_store": entry_to_store or [],
                "store_bypass": bypass_store or [],
                "clean_store_to_load": clean_after_store or [],
                "memory_effect_store_to_load": effect_after_store or [],
            },
            "claim_scope": (
                REACHING_CLAIM_SCOPE_V6 if indirect_effect_links_enabled
                else REACHING_CLAIM_SCOPE_V5 if interprocedural_effects_enabled
                else REACHING_CLAIM_SCOPE_V4 if call_effect_closures_enabled
                else REACHING_CLAIM_SCOPE_V3 if direct_call_effects_enabled
                else REACHING_CLAIM_SCOPE_V2 if access_facts_enabled
                else "Conservative single-function High-P-code structural candidate; no branch-feasibility, alias-disambiguation, or runtime value-flow claim."
            ),
            "provenance": {
                "pair_graph_sha256": pair_graph_sha256,
                "pair_graph_record_index": pair_index,
                "cfg_sha256": cfg_sha256,
                "cfg_record_index": cfg_record_index,
                "path_expansion_cap": max_path_expansions,
                "path_expansions_before": before,
                "path_expansions_used": path_expansions - before,
            },
        }
        if access_facts_enabled:
            result["provenance"].update({
                "memory_store_access_sha256": memory_store_access_sha256,
                "memory_store_access_record_indices": memory_access_indices,
                "memory_access_comparison_cap": max_memory_access_comparisons,
                "memory_access_comparisons_before": memory_comparisons_before,
                "memory_access_comparisons_used": memory_access_comparisons - memory_comparisons_before,
            })
        if direct_call_effects_enabled:
            result["provenance"].update({
                "direct_call_memory_effect_sha256": direct_call_memory_effect_sha256,
                "direct_call_memory_effect_record_indices": call_effect_indices,
            })
        if call_effect_closures_enabled:
            result["provenance"].update({
                "direct_call_memory_effect_closure_sha256": direct_call_memory_effect_closure_sha256,
                "direct_call_memory_effect_closure_record_indices": call_effect_indices,
            })
        if interprocedural_effects_enabled:
            result["provenance"].update({
                "interprocedural_memory_effect_sha256": interprocedural_memory_effect_sha256,
                "interprocedural_memory_effect_record_indices": call_effect_indices,
            })
        output.append(result)
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("field_access_pairs", type=Path)
    parser.add_argument("function_pcode_cfg", type=Path)
    parser.add_argument("--max-pairs", type=int, default=100_000)
    parser.add_argument("--max-path-expansions", type=int, default=1_000_000)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    pair_sha, pair_graphs = _read_jsonl(args.field_access_pairs)
    cfg_sha, cfg_records = _read_jsonl(args.function_pcode_cfg)
    rows = audit_field_store_load_paths(
        pair_graphs, cfg_records, pair_graph_sha256=pair_sha,
        cfg_sha256=cfg_sha, max_pairs=args.max_pairs,
        max_path_expansions=args.max_path_expansions,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    print("field-access pairs:", len(rows))
    print("candidate paths:", sum(row["status"] == "candidate_path_compatible" for row in rows))
    print("output:", args.output)
    return 0


def dominance_main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit whether a paired field store is the unique conservative CFG candidate at a load.")
    parser.add_argument("field_access_pairs", type=Path)
    parser.add_argument("function_pcode_cfg", type=Path)
    parser.add_argument("--memory-store-access-jsonl", type=Path)
    parser.add_argument("--direct-call-memory-effect-jsonl", type=Path)
    parser.add_argument("--direct-call-memory-effect-closure-jsonl", type=Path)
    parser.add_argument("--interprocedural-memory-effect-jsonl", type=Path)
    parser.add_argument("--max-pairs", type=int, default=100_000)
    parser.add_argument("--max-path-expansions", type=int, default=1_000_000)
    parser.add_argument("--max-memory-access-comparisons", type=int, default=1_000_000)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    pair_sha, pair_graphs = _read_jsonl(args.field_access_pairs)
    cfg_sha, cfg_records = _read_jsonl(args.function_pcode_cfg)
    if args.memory_store_access_jsonl is None:
        access_sha, access_rows = None, None
    else:
        access_sha, access_rows = _read_jsonl(args.memory_store_access_jsonl)
    if args.direct_call_memory_effect_jsonl is None:
        call_effect_sha, call_effect_rows = None, None
    else:
        call_effect_sha, call_effect_rows = _read_jsonl(args.direct_call_memory_effect_jsonl)
    if args.direct_call_memory_effect_closure_jsonl is None:
        call_effect_closure_sha, call_effect_closure_rows = None, None
    else:
        call_effect_closure_sha, call_effect_closure_rows = _read_jsonl(args.direct_call_memory_effect_closure_jsonl)
    if args.interprocedural_memory_effect_jsonl is None:
        interprocedural_memory_effect_sha, interprocedural_memory_effect_rows = None, None
    else:
        interprocedural_memory_effect_sha, interprocedural_memory_effect_rows = _read_jsonl(
            args.interprocedural_memory_effect_jsonl
        )
    rows = audit_field_store_load_dominance(
        pair_graphs, cfg_records, pair_graph_sha256=pair_sha,
        memory_store_access_rows=access_rows, memory_store_access_sha256=access_sha,
        direct_call_memory_effect_rows=call_effect_rows,
        direct_call_memory_effect_sha256=call_effect_sha,
        direct_call_memory_effect_closure_rows=call_effect_closure_rows,
        direct_call_memory_effect_closure_sha256=call_effect_closure_sha,
        interprocedural_memory_effect_rows=interprocedural_memory_effect_rows,
        interprocedural_memory_effect_sha256=interprocedural_memory_effect_sha,
        cfg_sha256=cfg_sha, max_pairs=args.max_pairs,
        max_path_expansions=args.max_path_expansions,
        max_memory_access_comparisons=args.max_memory_access_comparisons,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    print("field-access pairs:", len(rows))
    print("unique CFG store candidates:", sum(row["status"] == "unique_cfg_store_candidate" for row in rows))
    print("output:", args.output)
    return 0
