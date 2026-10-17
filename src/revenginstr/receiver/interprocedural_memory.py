"""Audit transitive direct-call writes against one parameter-rooted field pair."""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

from revenginstr.pcode.opcodes import NO_EXPLICIT_MEMORY_WRITE_OPCODES
from .call_effects import MAX_FLOW_BYTES, MAX_FLOW_OPERATIONS, _read_callee_flows
from .field_flow import (
    _index_cfg,
    _index_memory_store_accesses,
    _memory_store_non_alias_reason,
    _pair_identity,
    _read_jsonl,
)

FORMAT = "REVENGINSTR.GhidraInterproceduralMemoryEffect/1"
PARAMETER_ROOT_FORMAT = "REVENGINSTR.GhidraCallerArgumentParameterRoot/1"
PARAMETER_ROOT_HEADER = (
    "format", "plan_id", "callee_entry", "parameter_index", "caller_entry",
    "caller_call_site", "caller_parameter_index", "argument_node_id", "status",
)
MAX_PAIRS = 100_000
MAX_FUNCTIONS = 10_000
MAX_CALLS = 100_000
MAX_EFFECT_ROWS = 1_000_000
MAX_MEMORY_COMPARISONS = 1_000_000


def _hash_json(value: Any) -> str:
    payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _read_parameter_roots(path: Path, flows: dict[str, tuple[str, list[dict[str, str]]]]) -> tuple[str, dict[tuple[str, str, int, str, int], tuple[int, int]]]:
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"{path}: input must be UTF-8") from error
    reader = csv.DictReader(io.StringIO(text, newline=""), delimiter="\t", strict=True)
    if tuple(reader.fieldnames or ()) != PARAMETER_ROOT_HEADER:
        raise ValueError(f"{path}: unexpected caller parameter-root TSV header")

    calls_by_site: dict[tuple[str, str, str], list[tuple[int, dict[str, str]]]] = defaultdict(list)
    for entry, (_, rows) in flows.items():
        for index, row in enumerate(rows, 1):
            if row["opcode"] == "CALL":
                calls_by_site[(entry, row["op_address"], row["callee_entry"])].append((index, row))

    roots: dict[tuple[str, str, int, str, int], tuple[int, int]] = {}
    for record_index, row in enumerate(reader, 2):
        if None in row or any(value is None for value in row.values()):
            raise ValueError(f"{path}:{record_index}: malformed TSV record")
        if row["format"] != PARAMETER_ROOT_FORMAT or row["status"] != "direct_parameter_root":
            raise ValueError(f"{path}:{record_index}: unsupported parameter-root row")
        if not row["plan_id"] or not row["callee_entry"] or row["callee_entry"] == "-":
            raise ValueError(f"{path}:{record_index}: invalid plan or callee identity")
        if not row["caller_entry"] or not row["caller_call_site"] or row["caller_call_site"] == "-":
            raise ValueError(f"{path}:{record_index}: invalid caller identity")
        raw_indices = (row["parameter_index"], row["caller_parameter_index"], row["argument_node_id"])
        if any(not value.isascii() or not value.isdecimal() for value in raw_indices):
            raise ValueError(f"{path}:{record_index}: parameter indices must be decimal strings")
        try:
            callee_parameter, caller_parameter, node_index = map(int, raw_indices)
        except ValueError as error:
            raise ValueError(f"{path}:{record_index}: parameter indices must be integers") from error
        if min(callee_parameter, caller_parameter, node_index) < 0:
            raise ValueError(f"{path}:{record_index}: parameter indices must be non-negative")
        if node_index != 0:
            raise ValueError(f"{path}:{record_index}: parameter root must identify the argument root node")
        if row["caller_entry"] not in flows:
            continue
        matches = calls_by_site.get((row["caller_entry"], row["caller_call_site"], row["callee_entry"]), [])
        if len(matches) != 1:
            raise ValueError(f"{path}:{record_index}: caller-root row does not identify one exact P-code CALL")
        call_index, call = matches[0]
        arguments = [] if call["inputs"] == "-" else call["inputs"].split(";")
        if callee_parameter >= len(arguments):
            raise ValueError(f"{path}:{record_index}: callee parameter exceeds the P-code call arguments")
        key = (row["caller_entry"], row["caller_call_site"], call_index, row["callee_entry"], callee_parameter)
        if key in roots:
            raise ValueError(f"{path}:{record_index}: duplicate caller parameter-root mapping")
        roots[key] = (caller_parameter, record_index)
    return hashlib.sha256(raw).hexdigest(), roots


def _call_arguments(row: dict[str, str]) -> list[str]:
    if row["inputs"] == "-":
        return []
    arguments = row["inputs"].split(";")
    if any(not value for value in arguments):
        raise ValueError("P-code CALL has an empty argument token")
    return arguments


def build_interprocedural_memory_effects(
    pair_graph_path: Path,
    cfg_path: Path,
    memory_store_access_path: Path,
    caller_parameter_roots_path: Path,
    *,
    pcode_flows: list[tuple[str, Path]],
    max_pairs: int = MAX_PAIRS,
    max_functions: int = MAX_FUNCTIONS,
    max_calls: int = MAX_CALLS,
    max_effect_rows: int = MAX_EFFECT_ROWS,
    max_flow_bytes: int = MAX_FLOW_BYTES,
    max_flow_operations: int = MAX_FLOW_OPERATIONS,
    max_memory_comparisons: int = MAX_MEMORY_COMPARISONS,
) -> list[dict[str, Any]]:
    """Build per-pair call effects, proving only exact-root disjoint writes harmless.

    Missing argument-root facts and distinct formal parameters remain may-alias
    states. Cycles are handled by a finite, monotone parameter-root dataflow.
    """
    if min(
        max_pairs, max_functions, max_calls, max_effect_rows, max_flow_bytes,
        max_flow_operations, max_memory_comparisons,
    ) < 1:
        raise ValueError("analysis budgets must be positive")
    pair_sha, pair_graphs = _read_jsonl(pair_graph_path)
    cfg_sha, cfg_rows = _read_jsonl(cfg_path)
    memory_sha, memory_rows = _read_jsonl(memory_store_access_path)
    if len(pair_graphs) > max_pairs:
        raise ValueError(f"field pair budget exceeded: {max_pairs}")
    pair_identities = [_pair_identity(graph, index) for index, graph in enumerate(pair_graphs, 1)]
    program_ids = {identity["program_id"] for identity in pair_identities}
    if len(program_ids) != 1:
        raise ValueError("field pairs must belong to one program")
    program_id = next(iter(program_ids))
    if len(pcode_flows) > max_functions or len(pcode_flows) < 1:
        raise ValueError(f"P-code flow function budget exceeded: {max_functions}")
    flow_bytes = sum(path.stat().st_size for _, path in pcode_flows)
    if flow_bytes > max_flow_bytes:
        raise ValueError(f"P-code flow byte budget exceeded: {max_flow_bytes}")
    flows = _read_callee_flows(pcode_flows, max_operations=max_flow_operations)
    flow_operation_count = sum(len(rows) for _, rows in flows.values())
    if flow_operation_count > max_flow_operations:
        raise ValueError(f"P-code flow operation budget exceeded: {max_flow_operations}")
    flow_manifest = [
        {"function_entry": entry, "pcode_flow_sha256": digest, "pcode_flow_record_count": len(rows)}
        for entry, (digest, rows) in sorted(flows.items())
    ]
    flow_manifest_sha = _hash_json(flow_manifest)
    root_sha, root_mappings = _read_parameter_roots(caller_parameter_roots_path, flows)
    cfg_by_function = _index_cfg(cfg_rows)
    memory_by_operation, _, memory_record_indices = _index_memory_store_accesses(
        memory_rows, cfg_by_function,
    )

    calls_by_function: dict[str, list[tuple[int, dict[str, str]]]] = defaultdict(list)
    all_call_count = 0
    for entry, (_, rows) in flows.items():
        for record_index, row in enumerate(rows, 1):
            site = (row["op_address"], int(row["op_time"]))
            cfg_item = cfg_by_function.get((program_id, entry))
            if row["opcode"] in {"CALL", "CALLIND", "STORE"} and cfg_item is None:
                raise ValueError(f"P-code flow has no matching CFG function: {entry}")
            if row["opcode"] in {"CALL", "CALLIND", "STORE"}:
                operation = cfg_item[1]["operations"].get(site)
                if operation is None or operation[2] != row["opcode"]:
                    raise ValueError(f"P-code flow disagrees with CFG at {entry}:{site}")
            if row["opcode"] in {"CALL", "CALLIND"}:
                all_call_count += 1
                calls_by_function[entry].append((record_index, row))
    if all_call_count > max_calls:
        raise ValueError(f"direct call budget exceeded: {max_calls}")

    used_flows: set[str] = set()
    comparisons = 0
    output: list[dict[str, Any]] = []
    for pair_index, (graph, identity) in enumerate(zip(pair_graphs, pair_identities), 1):
        caller_entry = identity["function_entry"]
        if caller_entry not in flows:
            raise ValueError(f"field pair {pair_index}: caller P-code flow is missing")
        used_flows.add(caller_entry)
        pair_store_key = (program_id, caller_entry, identity["store_address"], identity["store_time"])
        tracked_access = memory_by_operation.get(pair_store_key)
        if (
            tracked_access is None
            or tracked_access["location_status"] != "parameter_rooted_constant_offset"
            or tracked_access["root_parameter_index"] != identity["parameter_index"]
            or tracked_access["offset_bytes"] != identity["field_offset"]
            or tracked_access["memory_width_bytes"] is None
        ):
            raise ValueError(f"field pair {pair_index}: tracked store lacks exact memory-access geometry")

        for caller_row_index, call in calls_by_function.get(caller_entry, []):
            address, time = call["op_address"], int(call["op_time"])
            opcode = call["opcode"]
            target = call["callee_entry"] if opcode == "CALL" and call["callee_entry"] != "-" else None
            caller_sha = flows[caller_entry][0]
            reachable: set[str] = set()
            stores: list[tuple[str, int, dict[str, Any]]] = []
            edges: list[tuple[str, int, dict[str, str], str]] = []
            unknown_ids: set[str] = set()
            effect_opcodes: set[str] = set()
            initial_arguments = _call_arguments(call)
            non_alias_indices: set[int] = set()
            alias_indices: set[int] = set()
            root_record_indices: set[int] = set()
            if opcode == "CALLIND":
                status = "indirect_call"
                unknown_ids.add(f"{caller_entry}:{address}:{time}:CALLIND")
                effect_opcodes.add("CALLIND")
            elif target is None:
                status = "unresolved_target"
                unknown_ids.add(f"{caller_entry}:{address}:{time}:CALL")
                effect_opcodes.add("CALL")
            elif target not in flows:
                status = "missing_callee_flow"
                unknown_ids.add(f"{caller_entry}:{address}:{time}:CALL")
                effect_opcodes.add("CALL")
            else:
                pending = deque([target])
                while pending:
                    function_entry = pending.popleft()
                    if function_entry in reachable:
                        continue
                    if function_entry not in flows:
                        continue
                    reachable.add(function_entry)
                    used_flows.add(function_entry)
                    _, function_rows = flows[function_entry]
                    for function_row_index, operation in enumerate(function_rows, 1):
                        site = (operation["op_address"], int(operation["op_time"]))
                        if operation["opcode"] == "STORE":
                            key = (program_id, function_entry, *site)
                            fact = memory_by_operation.get(key)
                            if fact is None:
                                effect_opcodes.add("STORE")
                                unknown_ids.add(
                                    f"{function_entry}:{site[0]}:{site[1]}:STORE:no_memory_access_fact"
                                )
                                continue
                            store_index = memory_record_indices[key]
                            stores.append((function_entry, store_index, fact))
                            effect_opcodes.add("STORE")
                        elif operation["opcode"] == "CALLIND":
                            effect_opcodes.add("CALLIND")
                            unknown_ids.add(f"{function_entry}:{site[0]}:{site[1]}:CALLIND")
                        elif operation["opcode"] == "CALL":
                            nested_target = operation["callee_entry"]
                            if nested_target == "-" or nested_target not in flows:
                                effect_opcodes.add("CALL")
                                unknown_ids.add(f"{function_entry}:{site[0]}:{site[1]}:CALL")
                            else:
                                edges.append((function_entry, function_row_index, operation, nested_target))
                                pending.append(nested_target)
                        elif operation["opcode"] not in NO_EXPLICIT_MEMORY_WRITE_OPCODES:
                            effect_opcodes.add(operation["opcode"])
                            unknown_ids.add(f"{function_entry}:{site[0]}:{site[1]}:{operation['opcode']}")

                # Compute whether every call path carries the tracked root into
                # each formal. Starting optimistic makes missing/ambiguous paths
                # monotonically downgrade a fact to may-alias.
                parameter_counts = defaultdict(int)
                for function_entry, _, fact in stores:
                    if fact["root_parameter_index"] is not None:
                        parameter_counts[function_entry] = max(
                            parameter_counts[function_entry], fact["root_parameter_index"] + 1,
                        )
                for source_entry, _, edge_call, callee_entry in edges:
                    parameter_counts[callee_entry] = max(parameter_counts[callee_entry], len(_call_arguments(edge_call)))
                parameter_counts[target] = max(parameter_counts[target], len(initial_arguments))
                states = {entry: [True] * parameter_counts[entry] for entry in reachable}
                seeds: dict[tuple[str, int], list[bool]] = defaultdict(list)
                for parameter in range(parameter_counts[target]):
                    mapping = root_mappings.get((caller_entry, address, caller_row_index, target, parameter))
                    if mapping is not None:
                        root_record_indices.add(mapping[1])
                    seeds[(target, parameter)].append(
                        mapping is not None and mapping[0] == identity["parameter_index"]
                        if parameter < len(initial_arguments) else False
                    )
                    states[target][parameter] = all(seeds[(target, parameter)])
                propagation_steps = 0
                changed = True
                while changed:
                    changed = False
                    for source_entry, call_index, edge_call, callee_entry in edges:
                        call_address = edge_call["op_address"]
                        arguments = _call_arguments(edge_call)
                        for parameter in range(parameter_counts[callee_entry]):
                            propagation_steps += 1
                            if propagation_steps > max_flow_operations:
                                raise ValueError("parameter-root propagation budget exceeded")
                            mapping = root_mappings.get((source_entry, call_address, call_index, callee_entry, parameter))
                            incoming = False
                            if parameter < len(arguments) and mapping is not None:
                                source_parameter = mapping[0]
                                source_states = states.get(source_entry, [])
                                incoming = source_parameter < len(source_states) and source_states[source_parameter]
                            key = (callee_entry, parameter)
                            if incoming not in seeds[key]:
                                seeds[key].append(incoming)
                            new_value = all(seeds[key])
                            old_value = states[callee_entry][parameter]
                            if old_value and not new_value:
                                states[callee_entry][parameter] = False
                                changed = True

                for source_entry, call_index, edge_call, callee_entry in edges:
                    arguments = _call_arguments(edge_call)
                    for parameter in range(min(len(arguments), parameter_counts[callee_entry])):
                        mapping = root_mappings.get((source_entry, edge_call["op_address"], call_index, callee_entry, parameter))
                        if mapping is not None:
                            root_record_indices.add(mapping[1])
                for function_entry, store_index, fact in stores:
                    comparisons += 1
                    if comparisons > max_memory_comparisons:
                        raise ValueError(f"memory access comparison budget exceeded: {max_memory_comparisons}")
                    exact_root = (
                        fact["root_parameter_index"] is not None
                        and fact["root_parameter_index"] < len(states[function_entry])
                        and states[function_entry][fact["root_parameter_index"]]
                    )
                    comparable_write = dict(fact)
                    comparable_write["root_parameter_index"] = (
                        identity["parameter_index"] if exact_root else None
                    )
                    reason = _memory_store_non_alias_reason(
                        tracked_access, comparable_write,
                        parameter_index=identity["parameter_index"],
                        field_offset=identity["field_offset"],
                        field_width=tracked_access["memory_width_bytes"],
                    )
                    if reason is None:
                        alias_indices.add(store_index)
                    else:
                        non_alias_indices.add(store_index)

                if unknown_ids:
                    status = "unknown_effect"
                elif alias_indices:
                    status = "possible_aliasing_write"
                else:
                    status = "no_aliasing_memory_effect"

            closure_entries = sorted(reachable)
            store_indices = sorted(index for _, index, _ in stores)
            root_indices = sorted(root_record_indices if target in flows and opcode == "CALL" else [])
            closure_sha = None
            if closure_entries:
                closure_sha = _hash_json({
                    "pair_graph_id": graph["graph_id"],
                    "root_call": [caller_entry, address, time, target],
                    "flow_manifest": [item for item in flow_manifest if item["function_entry"] in reachable],
                    "memory_store_access_record_indices": store_indices,
                    "caller_parameter_root_record_indices": root_indices,
                    "aliasing_store_record_indices": sorted(alias_indices),
                    "non_aliasing_store_record_indices": sorted(non_alias_indices),
                    "unknown_operation_ids": sorted(unknown_ids),
                })
            if len(output) >= max_effect_rows:
                raise ValueError(f"interprocedural effect row budget exceeded: {max_effect_rows}")
            output.append({
                "format": FORMAT,
                "program_id": program_id,
                "function_entry": caller_entry,
                "field_pair_id": graph["graph_id"],
                "address": address,
                "time": time,
                "opcode": opcode,
                "callee_entry": target,
                "status": status,
                "effect_opcodes": sorted(effect_opcodes),
                "aliasing_store_record_indices": sorted(alias_indices),
                "non_aliasing_store_record_indices": sorted(non_alias_indices),
                "provenance": {
                    "field_access_pair_graph_sha256": pair_sha,
                    "field_access_pair_graph_record_index": pair_index,
                    "cfg_sha256": cfg_sha,
                    "memory_store_access_sha256": memory_sha,
                    "memory_store_access_record_indices": store_indices,
                    "tracked_memory_store_access_record_index": memory_record_indices[pair_store_key],
                    "caller_parameter_roots_sha256": root_sha,
                    "caller_parameter_root_record_indices": root_indices,
                    "caller_pcode_flow_sha256": caller_sha,
                    "caller_pcode_flow_record_index": caller_row_index,
                    "pcode_flow_manifest_sha256": flow_manifest_sha,
                    "closure_sha256": closure_sha,
                    "closure_function_entries": closure_entries,
                    "unknown_operation_ids": sorted(unknown_ids),
                    "memory_access_comparisons": len(stores),
                },
            })

    unused = set(flows) - used_flows
    if unused:
        raise ValueError(f"P-code flow files are not used by any pair closure: {sorted(unused)}")
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("field_access_pairs", type=Path)
    parser.add_argument("function_pcode_cfg", type=Path)
    parser.add_argument("memory_store_access", type=Path)
    parser.add_argument("caller_parameter_roots", type=Path)
    parser.add_argument(
        "--pcode-flow", action="append", nargs=2, metavar=("ENTRY", "TSV"),
        required=True, help="One-function P-code flow in the bounded direct-call closure; repeat as needed.",
    )
    parser.add_argument("--max-pairs", type=int, default=MAX_PAIRS)
    parser.add_argument("--max-functions", type=int, default=MAX_FUNCTIONS)
    parser.add_argument("--max-calls", type=int, default=MAX_CALLS)
    parser.add_argument("--max-effect-rows", type=int, default=MAX_EFFECT_ROWS)
    parser.add_argument("--max-flow-bytes", type=int, default=MAX_FLOW_BYTES)
    parser.add_argument("--max-flow-operations", type=int, default=MAX_FLOW_OPERATIONS)
    parser.add_argument("--max-memory-comparisons", type=int, default=MAX_MEMORY_COMPARISONS)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    rows = build_interprocedural_memory_effects(
        args.field_access_pairs,
        args.function_pcode_cfg,
        args.memory_store_access,
        args.caller_parameter_roots,
        pcode_flows=[(entry, Path(path)) for entry, path in args.pcode_flow],
        max_pairs=args.max_pairs,
        max_functions=args.max_functions,
        max_calls=args.max_calls,
        max_effect_rows=args.max_effect_rows,
        max_flow_bytes=args.max_flow_bytes,
        max_flow_operations=args.max_flow_operations,
        max_memory_comparisons=args.max_memory_comparisons,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    print("field-call effects:", len(rows))
    print("no-alias:", sum(row["status"] == "no_aliasing_memory_effect" for row in rows))
    print("possible writes:", sum(row["status"] == "possible_aliasing_write" for row in rows))
    print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
