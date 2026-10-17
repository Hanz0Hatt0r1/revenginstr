"""Summarize direct-call memory effects across a bounded P-code call closure."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from revenginstr.pcode.opcodes import NO_EXPLICIT_MEMORY_WRITE_OPCODES
from .call_effects import (
    MAX_CALLS,
    MAX_FLOW_BYTES,
    MAX_FLOW_OPERATIONS,
    _read_callee_flows,
    _read_pcode_flow,
)

FORMAT = "REVENGINSTR.GhidraDirectCallMemoryEffectClosure/1"
MAX_FUNCTIONS = 10_000
MAX_CLOSURE_VISITS = 1_000_000


def _closure_summary(
    entry: str,
    flows: dict[str, tuple[str, list[dict[str, str]]]],
) -> tuple[set[str], set[str], int]:
    pending = [entry]
    reachable: set[str] = set()
    effects: set[str] = set()
    call_site_count = 0
    while pending:
        current = pending.pop()
        if current in reachable:
            continue
        flow = flows.get(current)
        if flow is None:
            effects.add("CALL")
            continue
        reachable.add(current)
        for row in flow[1]:
            opcode = row["opcode"]
            if opcode in {"CALL", "CALLIND"}:
                call_site_count += 1
                if opcode == "CALLIND":
                    effects.add("CALLIND")
                    continue
                target = row.get("callee_entry", "-")
                if not target or target == "-":
                    effects.add("CALL")
                elif target in flows:
                    pending.append(target)
                else:
                    effects.add("CALL")
            elif opcode == "STORE":
                effects.add("STORE")
            elif opcode not in NO_EXPLICIT_MEMORY_WRITE_OPCODES:
                effects.add(opcode)
    return reachable, effects, call_site_count


def _closure_digest(
    entries: set[str], flows: dict[str, tuple[str, list[dict[str, str]]]],
) -> str:
    manifest = [
        {
            "function_entry": entry,
            "pcode_flow_sha256": flows[entry][0],
            "pcode_flow_record_count": len(flows[entry][1]),
        }
        for entry in sorted(entries)
    ]
    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def build_direct_call_memory_effect_closure(
    program_id: str,
    caller_flow_tsv: Path,
    *,
    callee_flows: list[tuple[str, Path]] | None = None,
    max_calls: int = MAX_CALLS,
    max_flow_bytes: int = MAX_FLOW_BYTES,
    max_flow_operations: int = MAX_FLOW_OPERATIONS,
    max_functions: int = MAX_FUNCTIONS,
    max_closure_visits: int = MAX_CLOSURE_VISITS,
) -> list[dict[str, Any]]:
    """Summarize each caller call using a closed, cycle-safe direct-call graph.

    A row is write-free only when every reachable function has a complete flow,
    contains no STORE or unknown operation, and every nested direct call is
    resolved by the supplied flow set. Cycles terminate through the visited-set
    walk; indirect calls and missing nested flows remain barriers.
    """
    if not program_id:
        raise ValueError("program_id must be non-empty")
    if max_calls < 1:
        raise ValueError("max_calls must be positive")
    if min(max_flow_bytes, max_flow_operations, max_functions, max_closure_visits) < 1:
        raise ValueError("P-code flow budgets must be positive")

    callee_flows = callee_flows or []
    paths = [caller_flow_tsv, *(path for _, path in callee_flows)]
    if sum(path.stat().st_size for path in paths) > max_flow_bytes:
        raise ValueError(f"P-code flow byte budget exceeded: {max_flow_bytes}")

    caller_sha, caller_rows = _read_pcode_flow(
        caller_flow_tsv, max_operations=max_flow_operations
    )
    caller_entry = caller_rows[0]["function_entry"]
    available = _read_callee_flows(callee_flows, max_operations=max_flow_operations)
    caller_flow = (caller_sha, caller_rows)
    if caller_entry in available:
        if available[caller_entry][0] != caller_sha:
            raise ValueError("callee flow for caller entry conflicts with caller input")
        del available[caller_entry]
    flows = {caller_entry: caller_flow, **available}
    if len(flows) > max_functions:
        raise ValueError(f"P-code flow function budget exceeded: {max_functions}")
    if sum(len(rows) for _, rows in flows.values()) > max_flow_operations:
        raise ValueError(f"P-code flow operation budget exceeded: {max_flow_operations}")

    caller_calls = [
        (index, row)
        for index, row in enumerate(caller_rows, 1)
        if row["opcode"] in {"CALL", "CALLIND"}
    ]
    if not caller_calls:
        raise ValueError("caller P-code flow contains no CALL or CALLIND operations")

    reachable_union: set[str] = set()
    total_call_sites = sum(
        row["opcode"] in {"CALL", "CALLIND"}
        for _, rows in flows.values()
        for row in rows
    )
    if total_call_sites > max_calls:
        raise ValueError(f"direct call memory effect budget exceeded: {max_calls}")

    summaries: dict[str, tuple[set[str], set[str], int]] = {}
    closure_visits = 0

    def summarize(entry: str) -> tuple[set[str], set[str], int]:
        nonlocal closure_visits
        if entry not in summaries:
            summary = _closure_summary(entry, flows)
            closure_visits += len(summary[0])
            if closure_visits > max_closure_visits:
                raise ValueError(f"call closure visit budget exceeded: {max_closure_visits}")
            summaries[entry] = summary
        return summaries[entry]

    closure_output_entries = 0
    for _, row in caller_calls:
        target = row.get("callee_entry", "-")
        if row["opcode"] == "CALL" and target not in {"", "-"} and target in flows:
            reachable, _, _ = summarize(target)
            reachable_union.update(reachable)
            closure_output_entries += len(reachable)
            if closure_visits + closure_output_entries > max_closure_visits:
                raise ValueError(f"call closure visit budget exceeded: {max_closure_visits}")
    unused = set(available) - reachable_union
    if unused:
        raise ValueError(f"callee flows are not reachable from caller P-code: {sorted(unused)}")

    result = []
    for record_index, row in caller_calls:
        opcode = row["opcode"]
        callee_entry = row.get("callee_entry") if opcode == "CALL" and row.get("callee_entry") != "-" else None
        callee_flow = flows.get(callee_entry) if callee_entry is not None else None
        callee_sha = None if callee_flow is None else callee_flow[0]
        callee_rows = [] if callee_flow is None else callee_flow[1]
        closure_sha = None
        closure_entries: list[str] = []
        closure_calls = 0
        if opcode == "CALLIND":
            status, effect_opcodes = "indirect_call", []
        elif callee_entry is None:
            status, effect_opcodes = "unresolved_target", []
        elif callee_flow is None:
            status, effect_opcodes = "missing_callee_flow", []
        else:
            reachable, effects, closure_calls = summarize(callee_entry)
            closure_entries = sorted(reachable)
            closure_sha = _closure_digest(reachable, flows)
            effect_opcodes = sorted(effects)
            if "STORE" in effects:
                status = "explicit_memory_write"
            elif effects:
                status = "unknown_effect"
            else:
                status = "no_explicit_memory_write"
        result.append({
            "format": FORMAT,
            "program_id": program_id,
            "function_entry": caller_entry,
            "address": row["op_address"],
            "time": int(row["op_time"]),
            "opcode": opcode,
            "callee_entry": callee_entry,
            "status": status,
            "effect_opcodes": effect_opcodes,
            "provenance": {
                "caller_pcode_flow_sha256": caller_sha,
                "caller_pcode_flow_record_index": record_index,
                "callee_pcode_flow_sha256": callee_sha,
                "callee_pcode_flow_record_count": len(callee_rows),
                "closure_sha256": closure_sha,
                "closure_function_entries": closure_entries,
                "closure_call_site_count": closure_calls,
            },
        })
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("caller_pcode_flow", type=Path)
    parser.add_argument("--program-id", required=True, help="Opaque consumer join key.")
    parser.add_argument(
        "--callee-flow", action="append", nargs=2, metavar=("ENTRY", "TSV"),
        default=[], help="One-function P-code flow in the transitive direct-call closure; repeat as needed.",
    )
    parser.add_argument("--max-calls", type=int, default=MAX_CALLS)
    parser.add_argument("--max-flow-bytes", type=int, default=MAX_FLOW_BYTES)
    parser.add_argument("--max-flow-operations", type=int, default=MAX_FLOW_OPERATIONS)
    parser.add_argument("--max-functions", type=int, default=MAX_FUNCTIONS)
    parser.add_argument("--max-closure-visits", type=int, default=MAX_CLOSURE_VISITS)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    rows = build_direct_call_memory_effect_closure(
        args.program_id,
        args.caller_pcode_flow,
        callee_flows=[(entry, Path(path)) for entry, path in args.callee_flow],
        max_calls=args.max_calls,
        max_flow_bytes=args.max_flow_bytes,
        max_flow_operations=args.max_flow_operations,
        max_functions=args.max_functions,
        max_closure_visits=args.max_closure_visits,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    print("call sites:", len(rows))
    print("status counts:", json.dumps(counts, sort_keys=True))
    print("output:", args.output)
    return 0
