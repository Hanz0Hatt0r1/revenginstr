"""Normalize direct-call argument observations from Ghidra P-code flow TSVs."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

FORMAT = "REVENGINSTR.DirectCallArgumentObservation/1"
SOURCE_FORMAT = "REVENGINSTR.GhidraFunctionPcodeFlow/1"
FLOW_COLUMNS = {
    "function_entry", "op_address", "op_time", "opcode", "output", "inputs",
    "callee_entry", "callee_name",
}
_ADDRESS = re.compile(r"^(?:[A-Za-z_$][\w$]*:)?(?:0x)?[0-9a-fA-F]+$")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _address(value: str, where: str) -> str:
    if not value or not _ADDRESS.fullmatch(value):
        raise ValueError(f"{where}: invalid address {value!r}")
    return value


def _arguments(value: str, where: str) -> list[dict[str, Any]]:
    if value == "-":
        return []
    if not value:
        raise ValueError(f"{where}: missing inputs; use '-' for no arguments")
    result = []
    for index, token in enumerate(value.split(";")):
        width = token.rpartition(":")[2]
        if not token or not width.isdecimal() or int(width) < 1:
            raise ValueError(f"{where}: input {index} has no positive byte width")
        result.append({"index": index, "value_token": token, "width_bytes": int(width)})
    return result


def observe_call_arguments(paths: list[Path], *, program_id: str) -> list[dict[str, Any]]:
    """Return one evidence-linked row per resolved direct P-code CALL site."""
    if not paths:
        raise ValueError("at least one Ghidra P-code flow TSV is required")
    if not isinstance(program_id, str) or not program_id:
        raise ValueError("program_id must be non-empty")
    observations = []
    call_sites: set[tuple[str, str, str]] = set()
    seen_paths: set[Path] = set()
    for path in sorted((path.resolve() for path in paths), key=str):
        if path in seen_paths:
            continue
        seen_paths.add(path)
        digest = _sha256(path)
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle, delimiter="\t")
            if reader.fieldnames is None or len(reader.fieldnames) != len(set(reader.fieldnames)) or set(reader.fieldnames) != FLOW_COLUMNS:
                raise ValueError(f"{path}: expected exact GhidraFunctionPcodeFlow/1 columns")
            for record_index, row in enumerate(reader, 1):
                where = f"{path}:data-row-{record_index}"
                if None in row or any(value is None for value in row.values()):
                    raise ValueError(f"{where}: malformed TSV row")
                if row["opcode"] != "CALL":
                    continue
                target = row["callee_entry"]
                if target == "-":
                    continue
                caller = _address(row["function_entry"], f"{where}: function_entry")
                call_address = _address(row["op_address"], f"{where}: op_address")
                callee = _address(target, f"{where}: callee_entry")
                call_time = row["op_time"]
                if not call_time.isdecimal():
                    raise ValueError(f"{where}: op_time must be a non-negative decimal integer")
                identity = (caller, call_address, str(int(call_time)))
                if identity in call_sites:
                    raise ValueError(f"{where}: duplicate direct call site {identity}")
                call_sites.add(identity)
                arguments = _arguments(row["inputs"], where)
                observations.append({
                    "format": FORMAT,
                    "program_id": program_id,
                    "caller_entry": caller,
                    "callee_entry": callee,
                    "call_address": call_address,
                    "call_time": int(call_time),
                    "argument_count": len(arguments),
                    "arguments": arguments,
                    "evidence_ref": {
                        "artifact_sha256": digest,
                        "record_index": record_index,
                        "source_format": SOURCE_FORMAT,
                    },
                })
    return observations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("flows", nargs="+", type=Path, help="GhidraFunctionPcodeFlow/1 TSV files")
    parser.add_argument("--program-id", required=True, help="stable id for the single analyzed program")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        rows = observe_call_arguments(args.flows, program_id=args.program_id)
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    print("format:", FORMAT)
    print("direct call sites:", len(rows))
    print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
