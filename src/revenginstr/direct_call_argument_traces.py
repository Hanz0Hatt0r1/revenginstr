"""Trace bounded P-code operand use/def references from direct-call arguments."""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

from revenginstr.direct_call_argument_definitions import (
    CALL_FORMAT,
    DEFINITION,
    FORMAT as DEFINITION_FORMAT,
    PCODE_FORMAT,
    _read_pcode_flows,
    resolve_call_argument_definitions,
)

FORMAT = "REVENGINSTR.DirectCallArgumentOperandTrace/1"
BOUNDARY_OPCODES = {"CALL", "CALLIND", "INDIRECT", "LOAD"}
MAX_TRACE_DEPTH = 64
MAX_TRACE_NODES = 4096


def _ref(artifact_sha256: str, record_index: int, source_format: str) -> dict[str, Any]:
    return {
        "artifact_sha256": artifact_sha256,
        "record_index": record_index,
        "source_format": source_format,
    }


def _inputs(row: dict[str, Any]) -> list[str]:
    if row["inputs"] == "-":
        return []
    operands = row["inputs"].split(";")
    if any(not operand for operand in operands):
        raise ValueError(
            "empty P-code input token at "
            f"{row['function_entry']}:{row['op_address']}#{row['op_time']}"
        )
    return operands


def _trace_one(
    observation: dict[str, Any],
    observation_index: int,
    argument: dict[str, Any],
    definition: dict[str, Any],
    definition_index: int,
    *,
    observations_sha256: str,
    definitions_sha256: str,
    pcode_rows: list[dict[str, Any]],
    pcode_sha256: str,
    definitions_by_output: dict[tuple[str, str], list[dict[str, Any]]],
    max_depth: int,
    max_nodes: int,
) -> dict[str, Any]:
    call_ref = observation["evidence_ref"]
    definition_refs = definition["definition_evidence_refs"]
    state = definition["resolution_state"]
    root_refs = [
        _ref(ref["artifact_sha256"], ref["record_index"], ref["source_format"])
        for ref in definition_refs
    ]
    nodes: dict[int, dict[str, Any]] = {}
    expanded: set[int] = set()
    active: set[int] = set()
    operand_edges: list[dict[str, Any]] = []
    leaf_operands: list[dict[str, Any]] = []
    unresolved_operands: list[dict[str, Any]] = []
    boundary_rows: list[dict[str, Any]] = []
    cycle_edges: list[dict[str, Any]] = []

    def unresolved(
        consumer_index: int,
        input_index: int,
        token: str,
        resolution: str,
        candidates: list[dict[str, Any]],
    ) -> None:
        unresolved_operands.append({
            "consumer_ref": _ref(pcode_sha256, consumer_index, PCODE_FORMAT),
            "input_index": input_index,
            "value_token": token,
            "resolution_state": resolution,
            "candidate_refs": candidates,
        })

    def visit(row: dict[str, Any], depth: int) -> None:
        record_index = row["_record_index"]
        if not row["opcode"]:
            raise ValueError(f"empty P-code opcode on producer record {record_index}")
        if record_index in expanded or record_index in active:
            return
        nodes[record_index] = {
            "evidence_ref": _ref(pcode_sha256, record_index, PCODE_FORMAT),
            "function_entry": row["function_entry"],
            "operation_address": row["op_address"],
            "operation_time": int(row["op_time"]),
            "opcode": row["opcode"],
            "output_token": row["output"],
            "inputs": _inputs(row),
            "callee_entry": row["callee_entry"],
            "callee_name": row["callee_name"],
        }
        active.add(record_index)
        operands = _inputs(row)
        if row["opcode"] in BOUNDARY_OPCODES:
            boundary_reason = {
                "CALL": "call_return_value",
                "CALLIND": "indirect_call_return_value",
                "INDIRECT": "indirect_operation_result",
                "LOAD": "memory_read_value",
            }[row["opcode"]]
            boundary_rows.append({
                "evidence_ref": _ref(pcode_sha256, record_index, PCODE_FORMAT),
                "opcode": row["opcode"],
                "boundary_reason": boundary_reason,
                "operands": [
                    {"input_index": index, "value_token": token}
                    for index, token in enumerate(operands)
                ],
            })
            active.remove(record_index)
            expanded.add(record_index)
            return

        for input_index, token in enumerate(operands):
            if not token.startswith("def:"):
                leaf_operands.append({
                    "consumer_ref": _ref(pcode_sha256, record_index, PCODE_FORMAT),
                    "input_index": input_index,
                    "value_token": token,
                    "token_kind": token.partition(":")[0],
                })
                continue
            candidates = definitions_by_output.get((observation["caller_entry"], token), [])
            candidate_refs = [
                _ref(pcode_sha256, candidate["_record_index"], PCODE_FORMAT)
                for candidate in candidates
            ]
            if len(candidates) != 1:
                unresolved(
                    record_index,
                    input_index,
                    token,
                    "ambiguous_definition" if candidates else "definition_not_found",
                    candidate_refs,
                )
                continue
            producer = candidates[0]
            producer_index = producer["_record_index"]
            if depth >= max_depth and producer_index not in nodes:
                unresolved(record_index, input_index, token, "depth_limit", candidate_refs)
                continue
            if producer_index not in nodes and len(nodes) >= max_nodes:
                unresolved(record_index, input_index, token, "node_limit", candidate_refs)
                continue
            edge = {
                "consumer_ref": _ref(pcode_sha256, record_index, PCODE_FORMAT),
                "producer_ref": _ref(pcode_sha256, producer_index, PCODE_FORMAT),
                "input_index": input_index,
                "value_token": token,
            }
            if producer_index in active:
                cycle_edges.append(edge)
                continue
            operand_edges.append(edge)
            if producer_index not in expanded:
                visit(producer, depth + 1)
        active.remove(record_index)
        expanded.add(record_index)

    if state == "exact_definition":
        root_index = definition_refs[0]["record_index"]
        root_row = pcode_rows[root_index - 1]
        visit(root_row, 1)

    trace_state = state
    if state == "exact_definition":
        if any(item["resolution_state"] == "node_limit" for item in unresolved_operands):
            trace_state = "node_limit"
        elif any(item["resolution_state"] == "depth_limit" for item in unresolved_operands):
            trace_state = "depth_limit"
        elif unresolved_operands:
            trace_state = "partial"
        elif cycle_edges:
            trace_state = "cycle_present"
        elif boundary_rows:
            trace_state = "boundary_reached"
        else:
            trace_state = "closed"

    sort_ref = lambda item: item["record_index"]
    operand_edges.sort(key=lambda item: (
        sort_ref(item["consumer_ref"]), item["input_index"], sort_ref(item["producer_ref"]),
    ))
    cycle_edges.sort(key=lambda item: (
        sort_ref(item["consumer_ref"]), item["input_index"], sort_ref(item["producer_ref"]),
    ))
    leaf_operands.sort(key=lambda item: (
        sort_ref(item["consumer_ref"]), item["input_index"], item["value_token"],
    ))
    unresolved_operands.sort(key=lambda item: (
        sort_ref(item["consumer_ref"]), item["input_index"], item["value_token"],
    ))
    boundary_rows.sort(key=lambda item: sort_ref(item["evidence_ref"]))
    return {
        "format": FORMAT,
        "program_id": observation["program_id"],
        "program_sha256": observation["program_sha256"],
        "caller_entry": observation["caller_entry"],
        "callee_entry": observation["callee_entry"],
        "call_address": observation["call_address"],
        "call_time": observation["call_time"],
        "argument_index": argument["index"],
        "argument_count": observation["argument_count"],
        "value_token": argument["value_token"],
        "width_bytes": argument["width_bytes"],
        "call_observation_ref": _ref(observations_sha256, observation_index, CALL_FORMAT),
        "call_pcode_evidence_ref": _ref(
            call_ref["artifact_sha256"], call_ref["record_index"], call_ref["source_format"],
        ),
        "definition_analysis_ref": _ref(definitions_sha256, definition_index, DEFINITION_FORMAT),
        "definition_resolution_state": state,
        "trace_state": trace_state,
        "max_depth": max_depth,
        "max_nodes_per_argument": max_nodes,
        "root_use": {
            "consumer_ref": _ref(
                call_ref["artifact_sha256"], call_ref["record_index"], call_ref["source_format"],
            ),
            "input_index": argument["index"],
            "value_token": argument["value_token"],
        },
        "root_definition_refs": root_refs,
        "nodes": [nodes[index] for index in sorted(nodes)],
        "operand_edges": operand_edges,
        "leaf_operands": leaf_operands,
        "unresolved_operands": unresolved_operands,
        "boundary_rows": boundary_rows,
        "cycle_edges": cycle_edges,
    }


def trace_call_argument_operands(
    observations: list[dict[str, Any]],
    *,
    observations_sha256: str,
    definition_rows: list[dict[str, Any]],
    definitions_sha256: str,
    pcode_paths: list[Path],
    max_depth: int = MAX_TRACE_DEPTH,
    max_nodes_per_argument: int = MAX_TRACE_NODES,
) -> list[dict[str, Any]]:
    """Trace exact syntactic P-code operand references, without evaluating values."""
    if type(max_depth) is not int or not 1 <= max_depth <= 128:
        raise ValueError("max_depth must be an integer from 1 to 128")
    if type(max_nodes_per_argument) is not int or not 1 <= max_nodes_per_argument <= 100_000:
        raise ValueError("max_nodes_per_argument must be an integer from 1 to 100000")
    if (
        not isinstance(definitions_sha256, str)
        or len(definitions_sha256) != 64
        or any(char not in "0123456789abcdef" for char in definitions_sha256)
    ):
        raise ValueError("definitions_sha256 must be a lowercase SHA-256 digest")
    expected = resolve_call_argument_definitions(
        observations,
        observations_sha256=observations_sha256,
        pcode_paths=pcode_paths,
    )
    if definition_rows != expected:
        raise ValueError("definition sidecar does not match exact call-observation and P-code replay")

    pcode_by_artifact = _read_pcode_flows(pcode_paths)
    definitions_by_output_by_artifact: dict[
        str, dict[tuple[str, str], list[dict[str, Any]]]
    ] = {}
    for artifact_sha256, rows in pcode_by_artifact.items():
        by_output: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
        for row in rows:
            match = DEFINITION.fullmatch(row["output"])
            if (
                match is not None
                and row["op_address"] == match.group(1)
                and int(row["op_time"]) == int(match.group(2))
            ):
                by_output[(row["function_entry"], row["output"])].append(row)
        definitions_by_output_by_artifact[artifact_sha256] = by_output

    traces: list[dict[str, Any]] = []
    definition_index = 0
    for observation_index, observation in enumerate(observations, 1):
        for argument in observation["arguments"]:
            definition = definition_rows[definition_index]
            definition_index += 1
            artifact_sha256 = observation["evidence_ref"]["artifact_sha256"]
            pcode_rows = pcode_by_artifact[artifact_sha256]
            traces.append(_trace_one(
                observation,
                observation_index,
                argument,
                definition,
                definition_index,
                observations_sha256=observations_sha256,
                definitions_sha256=definitions_sha256,
                pcode_rows=pcode_rows,
                pcode_sha256=artifact_sha256,
                definitions_by_output=definitions_by_output_by_artifact[artifact_sha256],
                max_depth=max_depth,
                max_nodes=max_nodes_per_argument,
            ))
    return traces


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("call_arguments", type=Path, help="DirectCallArgumentObservation/1 JSONL")
    parser.add_argument("argument_definitions", type=Path, help="DirectCallArgumentDefinition/1 JSONL")
    parser.add_argument("pcode_flows", nargs="+", type=Path, help="source GhidraFunctionPcodeFlow/1 TSV files")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-depth", type=int, default=MAX_TRACE_DEPTH)
    parser.add_argument("--max-nodes-per-argument", type=int, default=MAX_TRACE_NODES)
    args = parser.parse_args(argv)
    try:
        from revenginstr.semantic_program_graph import _read_jsonl

        input_paths = {
            args.call_arguments.resolve(), args.argument_definitions.resolve(),
            *(path.resolve() for path in args.pcode_flows),
        }
        if args.output.resolve() in input_paths:
            raise ValueError("output path must not replace an input")
        observations, observations_sha256 = _read_jsonl(args.call_arguments)
        definition_rows, definitions_sha256 = _read_jsonl(args.argument_definitions)
        traces = trace_call_argument_operands(
            observations,
            observations_sha256=observations_sha256,
            definition_rows=definition_rows,
            definitions_sha256=definitions_sha256,
            pcode_paths=args.pcode_flows,
            max_depth=args.max_depth,
            max_nodes_per_argument=args.max_nodes_per_argument,
        )
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for row in traces:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    counts: dict[str, int] = defaultdict(int)
    for row in traces:
        counts[row["trace_state"]] += 1
    print("format:", FORMAT)
    print("arguments:", len(traces))
    print("trace states:", dict(sorted(counts.items())))
    print("P-code producer rows:", sum(len(row["nodes"]) for row in traces))
    print("operand references:", sum(len(row["operand_edges"]) for row in traces))
    print("unresolved operands:", sum(len(row["unresolved_operands"]) for row in traces))
    print("boundary rows:", sum(len(row["boundary_rows"]) for row in traces))
    print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
