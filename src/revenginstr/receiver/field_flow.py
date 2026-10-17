"""Audit same-field accesses for a bounded safe High-P-code CFG path."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import deque
from pathlib import Path
from typing import Any

from .provenance import FORMAT as GRAPH_FORMAT
from .provenance import PARAMETER_LOAD_FORMAT, PARAMETER_STORE_FORMAT, validate_graph_references

FORMAT = "REVENGINSTR.FieldStoreLoadPathAudit/1"
CFG_FORMAT = "REVENGINSTR.GhidraFunctionPcodeCFG/1"
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
        if (
            not isinstance(record, dict)
            or set(record) != {"format", "program_id", "function_entry", "blocks"}
            or record.get("format") != CFG_FORMAT
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
        blocks: dict[int, dict[str, Any]] = {}
        operations: dict[tuple[str, int], tuple[int, int, str]] = {}
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
                if not isinstance(operation, dict) or set(operation) != {"address", "time", "opcode"}:
                    raise ValueError(f"{where}: malformed operation")
                if not isinstance(operation["address"], str) or not operation["address"]:
                    raise ValueError(f"{where}: invalid operation address")
                operation_time = _int(operation["time"], f"{where} operation time")
                if not isinstance(operation["opcode"], str) or not operation["opcode"]:
                    raise ValueError(f"{where}: invalid opcode")
                key = (operation["address"], operation_time)
                if key in operations:
                    raise ValueError(f"{where}: duplicate operation location")
                operations[key] = (block_index, position, operation["opcode"])
                block_operations.append(operation)
            successors = [_int(value, f"{where} successor") for value in block["successors"]]
            if len(successors) != len(set(successors)):
                raise ValueError(f"{where}: duplicate successor")
            blocks[block_index] = {"operations": block_operations, "successors": successors}
        for block_index, block in blocks.items():
            if any(successor not in blocks for successor in block["successors"]):
                raise ValueError(f"{where} block {block_index}: dangling successor")
        indexed[identity_key] = (record_index, {"blocks": blocks, "operations": operations})
    return indexed


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
                status = "intervening_store_or_call" if any_path is not None else "no_cfg_path"
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
