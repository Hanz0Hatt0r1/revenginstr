"""Summarize direct-call memory-effect evidence from metadata-only P-code TSVs."""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path
from typing import Any

from revenginstr.pcode.opcodes import NO_EXPLICIT_MEMORY_WRITE_OPCODES

FORMAT = "REVENGINSTR.GhidraDirectCallMemoryEffect/1"
PCODE_HEADER = (
    "function_entry", "op_address", "op_time", "opcode", "output", "inputs",
    "callee_entry", "callee_name",
)
MAX_CALLS = 100_000
MAX_FLOW_BYTES = 64 * 1024 * 1024
MAX_FLOW_OPERATIONS = 1_000_000

def _read_pcode_flow(path: Path, *, max_operations: int) -> tuple[str, list[dict[str, str]]]:
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"{path}: input must be UTF-8") from error
    reader = csv.DictReader(io.StringIO(text, newline=""), delimiter="\t", strict=True)
    if tuple(reader.fieldnames or ()) != PCODE_HEADER:
        raise ValueError(f"{path}: unexpected TSV header")
    rows: list[dict[str, str]] = []
    function_entries: set[str] = set()
    seen_operations: set[tuple[str, str, int]] = set()
    for record_index, row in enumerate(reader, 1):
        if None in row or any(value is None for value in row.values()):
            raise ValueError(f"{path}: malformed TSV record {record_index}")
        for field in ("function_entry", "op_address", "opcode"):
            if not row[field] or row[field] == "-":
                raise ValueError(f"{path}:{record_index}: missing {field}")
        if not row["op_time"].isascii() or not row["op_time"].isdecimal():
            raise ValueError(f"{path}:{record_index}: invalid op_time")
        key = (row["function_entry"], row["op_address"], int(row["op_time"]))
        if key in seen_operations:
            raise ValueError(f"{path}:{record_index}: duplicate P-code operation identity")
        seen_operations.add(key)
        function_entries.add(row["function_entry"])
        rows.append(row)
        if len(rows) > max_operations:
            raise ValueError(f"{path}: P-code flow operation budget exceeded: {max_operations}")
    if not rows:
        raise ValueError(f"{path}: P-code flow artifact has no operation rows")
    if len(function_entries) != 1:
        raise ValueError(f"{path}: expected exactly one function, got {len(function_entries)}")
    return hashlib.sha256(raw).hexdigest(), rows


def _read_callee_flows(
    values: list[tuple[str, Path]], *, max_operations: int,
) -> dict[str, tuple[str, list[dict[str, str]]]]:
    result = {}
    for entry, path in values:
        if not entry or entry == "-":
            raise ValueError("callee function entry must be a known address")
        if entry in result:
            raise ValueError(f"duplicate callee flow for {entry}")
        digest, rows = _read_pcode_flow(path, max_operations=max_operations)
        actual_entries = {row["function_entry"] for row in rows}
        if actual_entries != {entry}:
            raise ValueError(f"{path}: expected P-code flow for callee {entry}")
        result[entry] = (digest, rows)
    return result


def build_direct_call_memory_effects(
    program_id: str,
    caller_flow_tsv: Path,
    *,
    callee_flows: list[tuple[str, Path]] | None = None,
    max_calls: int = MAX_CALLS,
    max_flow_bytes: int = MAX_FLOW_BYTES,
    max_flow_operations: int = MAX_FLOW_OPERATIONS,
) -> list[dict[str, Any]]:
    """Build exact call-site facts; only closed, write-free direct callees pass."""
    if not program_id:
        raise ValueError("program_id must be non-empty")
    if max_calls < 1:
        raise ValueError("max_calls must be positive")
    if max_flow_bytes < 1 or max_flow_operations < 1:
        raise ValueError("P-code flow budgets must be positive")
    callee_flows = callee_flows or []
    flow_bytes = sum(path.stat().st_size for path in [caller_flow_tsv, *(path for _, path in callee_flows)])
    if flow_bytes > max_flow_bytes:
        raise ValueError(f"P-code flow byte budget exceeded: {max_flow_bytes}")
    caller_sha, caller_rows = _read_pcode_flow(caller_flow_tsv, max_operations=max_flow_operations)
    caller_entry = caller_rows[0]["function_entry"]
    available = _read_callee_flows(callee_flows, max_operations=max_flow_operations)
    flow_operations = len(caller_rows) + sum(len(rows) for _, rows in available.values())
    if flow_operations > max_flow_operations:
        raise ValueError(f"P-code flow operation budget exceeded: {max_flow_operations}")
    call_rows = [
        (index, row) for index, row in enumerate(caller_rows, 1)
        if row["opcode"] in {"CALL", "CALLIND"}
    ]
    if not call_rows:
        raise ValueError("caller P-code flow contains no CALL or CALLIND operations")
    if len(call_rows) > max_calls:
        raise ValueError(f"direct call memory effect budget exceeded: {max_calls}")

    target_entries = {row["callee_entry"] for _, row in call_rows if row["opcode"] == "CALL" and row["callee_entry"] != "-"}
    unused = set(available) - target_entries
    if unused:
        raise ValueError(f"callee flows are not referenced by caller P-code: {sorted(unused)}")

    result = []
    for record_index, row in call_rows:
        opcode = row["opcode"]
        callee_entry = row["callee_entry"] if opcode == "CALL" and row["callee_entry"] != "-" else None
        callee_flow = available.get(callee_entry) if callee_entry is not None else None
        callee_sha = None if callee_flow is None else callee_flow[0]
        callee_rows = [] if callee_flow is None else callee_flow[1]
        if opcode == "CALLIND":
            status, effect_opcodes = "indirect_call", []
        elif callee_entry is None:
            status, effect_opcodes = "unresolved_target", []
        elif callee_flow is None:
            status, effect_opcodes = "missing_callee_flow", []
        else:
            callee_opcodes = {callee_row["opcode"] for callee_row in callee_rows}
            if "STORE" in callee_opcodes:
                status, effect_opcodes = "explicit_memory_write", ["STORE"]
            else:
                effect_opcodes = sorted(callee_opcodes - NO_EXPLICIT_MEMORY_WRITE_OPCODES)
                status = "unknown_effect" if effect_opcodes else "no_explicit_memory_write"
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
            },
        })
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("caller_pcode_flow", type=Path)
    parser.add_argument("--program-id", required=True, help="Opaque consumer join key.")
    parser.add_argument(
        "--callee-flow", action="append", nargs=2, metavar=("ENTRY", "TSV"),
        default=[], help="One-function P-code flow TSV for a resolved direct callee; repeat as needed.",
    )
    parser.add_argument("--max-calls", type=int, default=MAX_CALLS)
    parser.add_argument("--max-flow-bytes", type=int, default=MAX_FLOW_BYTES)
    parser.add_argument("--max-flow-operations", type=int, default=MAX_FLOW_OPERATIONS)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    rows = build_direct_call_memory_effects(
        args.program_id,
        args.caller_pcode_flow,
        callee_flows=[(entry, Path(path)) for entry, path in args.callee_flow],
        max_calls=args.max_calls,
        max_flow_bytes=args.max_flow_bytes,
        max_flow_operations=args.max_flow_operations,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    counts = {}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    print("call sites:", len(rows))
    print("status counts:", json.dumps(counts, sort_keys=True))
    print("output:", args.output)
    return 0
