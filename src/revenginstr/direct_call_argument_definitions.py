"""Resolve direct-call P-code definition tokens to exact source rows."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

FORMAT = "REVENGINSTR.DirectCallArgumentDefinition/1"
CALL_FORMAT = "REVENGINSTR.DirectCallArgumentObservation/1"
PCODE_FORMAT = "REVENGINSTR.GhidraFunctionPcodeFlow/1"
FLOW_COLUMNS = {
    "function_entry", "op_address", "op_time", "opcode", "output", "inputs",
    "callee_entry", "callee_name",
}
SHA256 = re.compile(r"^[0-9a-f]{64}$")
ADDRESS = re.compile(r"^(?:[A-Za-z_$][\w$]*:)?(?:0x)?[0-9a-fA-F]+$")
DEFINITION = re.compile(r"^def:([^:]+):([0-9]+):([1-9][0-9]*)$")
CALL_FIELDS = {
    "format", "program_id", "program_sha256", "caller_entry", "callee_entry",
    "call_address", "call_time", "argument_count", "arguments", "evidence_ref",
}


def _jsonl(path: Path) -> tuple[list[dict[str, Any]], str]:
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"{path}: input must be UTF-8") from error
    rows = []
    for line_no, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"{path}:{line_no}: invalid JSON: {error}") from error
        if not isinstance(row, dict):
            raise ValueError(f"{path}:{line_no}: expected a JSON object")
        rows.append(row)
    if not rows:
        raise ValueError(f"{path}: input is empty")
    return rows, hashlib.sha256(raw).hexdigest()


def _read_pcode_flows(paths: list[Path]) -> dict[str, list[dict[str, Any]]]:
    by_artifact: dict[str, list[dict[str, Any]]] = {}
    for path in sorted({path.resolve() for path in paths}, key=str):
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError(f"{path}: P-code input must be UTF-8") from error
        reader = csv.DictReader(text.splitlines(), delimiter="\t")
        if reader.fieldnames is None or len(reader.fieldnames) != len(set(reader.fieldnames)) or set(reader.fieldnames) != FLOW_COLUMNS:
            raise ValueError(f"{path}: expected exact GhidraFunctionPcodeFlow/1 columns")
        rows = []
        for record_index, row in enumerate(reader, 1):
            if None in row or any(not isinstance(value, str) for value in row.values()):
                raise ValueError(f"{path}: malformed P-code row {record_index}")
            if (
                not ADDRESS.fullmatch(row["function_entry"])
                or not ADDRESS.fullmatch(row["op_address"])
                or not row["op_time"].isdecimal()
            ):
                raise ValueError(f"{path}: invalid function/address/time on P-code row {record_index}")
            parsed = {**row, "_record_index": record_index}
            rows.append(parsed)
        by_artifact[digest] = rows
    if not by_artifact:
        raise ValueError("at least one Ghidra P-code flow TSV is required")
    return by_artifact


def _validate_call(row: dict[str, Any], index: int) -> None:
    where = f"call-argument observation {index}"
    if set(row) != CALL_FIELDS or row.get("format") != CALL_FORMAT:
        raise ValueError(f"{where}: malformed DirectCallArgumentObservation/1 fields")
    for key in ("program_id", "caller_entry", "callee_entry", "call_address"):
        if not isinstance(row.get(key), str) or not row[key]:
            raise ValueError(f"{where}: invalid {key}")
    for key in ("caller_entry", "callee_entry", "call_address"):
        if not ADDRESS.fullmatch(row[key]):
            raise ValueError(f"{where}: invalid {key}")
    if not isinstance(row.get("program_sha256"), str) or not SHA256.fullmatch(row["program_sha256"]):
        raise ValueError(f"{where}: invalid program_sha256")
    if type(row.get("call_time")) is not int or row["call_time"] < 0:
        raise ValueError(f"{where}: invalid call_time")
    args = row.get("arguments")
    if not isinstance(args, list) or type(row.get("argument_count")) is not int or row["argument_count"] != len(args):
        raise ValueError(f"{where}: argument_count disagrees with arguments")
    for argument_index, argument in enumerate(args):
        if not isinstance(argument, dict) or set(argument) != {"index", "value_token", "width_bytes"}:
            raise ValueError(f"{where}: malformed argument {argument_index}")
        if type(argument["index"]) is not int or argument["index"] != argument_index:
            raise ValueError(f"{where}: argument indices must be contiguous")
        if not isinstance(argument["value_token"], str) or not argument["value_token"]:
            raise ValueError(f"{where}: invalid argument value_token")
        if type(argument["width_bytes"]) is not int or argument["width_bytes"] < 1:
            raise ValueError(f"{where}: invalid argument width_bytes")
    reference = row.get("evidence_ref")
    if not isinstance(reference, dict) or set(reference) != {"artifact_sha256", "record_index", "source_format"}:
        raise ValueError(f"{where}: malformed evidence_ref")
    if (
        not isinstance(reference["artifact_sha256"], str)
        or not SHA256.fullmatch(reference["artifact_sha256"])
        or type(reference["record_index"]) is not int
        or reference["record_index"] < 1
        or reference["source_format"] != PCODE_FORMAT
    ):
        raise ValueError(f"{where}: invalid P-code evidence_ref")


def resolve_call_argument_definitions(
    observations: list[dict[str, Any]], *, observations_sha256: str,
    pcode_paths: list[Path],
) -> list[dict[str, Any]]:
    """Resolve `def:` tokens only to exact output rows from the same P-code artifact."""
    if not observations:
        raise ValueError("DirectCallArgumentObservation input is empty")
    if not SHA256.fullmatch(observations_sha256):
        raise ValueError("observations_sha256 must be a lowercase SHA-256")
    by_artifact = _read_pcode_flows(pcode_paths)
    definitions: dict[tuple[str, str, str, int], list[dict[str, Any]]] = defaultdict(list)
    for artifact_sha256, rows in by_artifact.items():
        for row in rows:
            token = row["output"]
            match = DEFINITION.fullmatch(token)
            if match is None:
                continue
            address, time, _width = match.groups()
            if row["op_address"] == address and int(row["op_time"]) == int(time):
                definitions[(artifact_sha256, row["function_entry"], address, int(time))].append(row)

    results = []
    seen_calls: set[tuple[str, str, str, int]] = set()
    program_identity: tuple[str, str] | None = None
    for observation_index, observation in enumerate(observations, 1):
        _validate_call(observation, observation_index)
        identity = (observation["program_id"], observation["program_sha256"])
        if program_identity is None:
            program_identity = identity
        elif identity != program_identity:
            raise ValueError("call observations contain multiple program identities")
        call_site = (
            observation["caller_entry"], observation["call_address"], observation["callee_entry"],
            observation["call_time"],
        )
        if call_site in seen_calls:
            raise ValueError(f"duplicate observed direct call site: {call_site}")
        seen_calls.add(call_site)

        call_ref = observation["evidence_ref"]
        source_rows = by_artifact.get(call_ref["artifact_sha256"])
        if source_rows is None:
            raise ValueError(f"call observation {observation_index}: source P-code artifact was not supplied")
        if call_ref["record_index"] > len(source_rows):
            raise ValueError(f"call observation {observation_index}: P-code record_index is out of range")
        source_call = source_rows[call_ref["record_index"] - 1]
        source_arguments = [] if source_call["inputs"] == "-" else source_call["inputs"].split(";")
        source_widths = []
        for token in source_arguments:
            width = token.rpartition(":")[2]
            if not width.isdecimal() or int(width) < 1:
                raise ValueError(f"call observation {observation_index}: source P-code has a malformed argument token")
            source_widths.append(int(width))
        if (
            source_call["opcode"] != "CALL"
            or source_call["function_entry"] != observation["caller_entry"]
            or source_call["op_address"] != observation["call_address"]
            or int(source_call["op_time"]) != observation["call_time"]
            or source_call["callee_entry"] != observation["callee_entry"]
            or source_arguments != [arg["value_token"] for arg in observation["arguments"]]
            or source_widths != [arg["width_bytes"] for arg in observation["arguments"]]
        ):
            raise ValueError(f"call observation {observation_index}: source P-code row does not match observation")

        for argument in observation["arguments"]:
            token = argument["value_token"]
            match = DEFINITION.fullmatch(token)
            refs = []
            if not token.startswith("def:"):
                state = "non_definition_token"
            elif match is None:
                state = "definition_not_found"
            else:
                address, time, width = match.groups()
                candidates = definitions.get((
                    call_ref["artifact_sha256"], observation["caller_entry"], address, int(time),
                ), [])
                candidates = [row for row in candidates if row["output"] == token and int(width) == argument["width_bytes"]]
                refs = [
                    {
                        "artifact_sha256": call_ref["artifact_sha256"],
                        "record_index": row["_record_index"],
                        "source_format": PCODE_FORMAT,
                    }
                    for row in candidates
                ]
                if len(refs) == 1:
                    state = "exact_definition"
                elif refs:
                    state = "ambiguous_definition"
                else:
                    state = "definition_not_found"
            results.append({
                "format": FORMAT,
                "program_id": observation["program_id"],
                "program_sha256": observation["program_sha256"],
                "caller_entry": observation["caller_entry"],
                "callee_entry": observation["callee_entry"],
                "call_address": observation["call_address"],
                "call_time": observation["call_time"],
                "argument_index": argument["index"],
                "argument_count": observation["argument_count"],
                "value_token": token,
                "width_bytes": argument["width_bytes"],
                "resolution_state": state,
                "call_observation_ref": {
                    "artifact_sha256": observations_sha256,
                    "record_index": observation_index,
                    "source_format": CALL_FORMAT,
                },
                "call_pcode_evidence_ref": call_ref,
                "definition_evidence_refs": sorted(refs, key=lambda ref: ref["record_index"]),
            })
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("call_arguments", type=Path, help="DirectCallArgumentObservation/1 JSONL")
    parser.add_argument("pcode_flows", nargs="+", type=Path, help="source GhidraFunctionPcodeFlow/1 TSV files")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        input_paths = {args.call_arguments.resolve(), *(path.resolve() for path in args.pcode_flows)}
        if args.output.resolve() in input_paths:
            raise ValueError("output path must not replace an input")
        observations, observations_sha256 = _jsonl(args.call_arguments)
        rows = resolve_call_argument_definitions(
            observations,
            observations_sha256=observations_sha256,
            pcode_paths=args.pcode_flows,
        )
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    counts: dict[str, int] = defaultdict(int)
    for row in rows:
        counts[row["resolution_state"]] += 1
    print("format:", FORMAT)
    print("arguments:", len(rows))
    print("resolution states:", dict(sorted(counts.items())))
    print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
