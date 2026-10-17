#!/usr/bin/env python3
"""Inventory machine P-code operations in a Ghidra function-instruction corpus."""
from __future__ import annotations

import argparse
import collections
import gzip
import hashlib
import json
from pathlib import Path
from typing import TextIO

FORMAT = "REVENGINSTR.PcodeInstructionCoverage/1"
INPUT_FORMAT = "REVENGINSTR.GhidraFunctionInstructions/1"


def open_text(path: Path) -> TextIO:
    if path.suffix.lower() == ".gz":
        return gzip.open(path, "rt", encoding="utf-8")
    return path.open("r", encoding="utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def audit(path: Path) -> dict:
    programs: set[str] = set()
    function_count = found_function_count = instruction_count = 0
    instructions_with_pcode = pcode_operation_count = 0
    opcode_counts: collections.Counter[str] = collections.Counter()
    no_pcode_mnemonics: collections.Counter[str] = collections.Counter()

    with open_text(path) as stream:
        for line_no, raw in enumerate(stream, 1):
            if not raw.strip():
                continue
            try:
                row = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSON: {exc.msg}") from exc
            if not isinstance(row, dict) or row.get("format") != INPUT_FORMAT:
                raise ValueError(f"{path}:{line_no}: expected {INPUT_FORMAT} row")

            program = row.get("program")
            if not isinstance(program, str) or not program:
                raise ValueError(f"{path}:{line_no}: program must be a non-empty string")
            programs.add(program)
            if len(programs) > 1:
                raise ValueError(f"{path}:{line_no}: mixed program identities")

            found = row.get("found")
            instructions = row.get("instructions")
            declared_count = row.get("instruction_count")
            if not isinstance(found, bool):
                raise ValueError(f"{path}:{line_no}: found must be a boolean")
            if not isinstance(instructions, list):
                raise ValueError(f"{path}:{line_no}: instructions must be a list")
            if type(declared_count) is not int or declared_count != len(instructions):
                raise ValueError(f"{path}:{line_no}: instruction_count does not match instructions")
            function = row.get("function")
            if found and not isinstance(function, dict):
                raise ValueError(f"{path}:{line_no}: a found function requires function metadata")
            if not found and function is not None:
                raise ValueError(f"{path}:{line_no}: a missing function must have null function metadata")
            if not found and instructions:
                raise ValueError(f"{path}:{line_no}: a missing function cannot contain instructions")

            function_count += 1
            found_function_count += int(found)
            instruction_count += len(instructions)
            for instruction_index, instruction in enumerate(instructions, 1):
                where = f"{path}:{line_no}: instruction {instruction_index}"
                if not isinstance(instruction, dict):
                    raise ValueError(f"{where}: expected object")
                mnemonic = instruction.get("mnemonic")
                operations = instruction.get("pcode")
                if not isinstance(mnemonic, str) or not mnemonic.strip():
                    raise ValueError(f"{where}: mnemonic must be a non-empty string")
                if not isinstance(operations, list):
                    raise ValueError(f"{where}: pcode must be a list")
                if not operations:
                    no_pcode_mnemonics[mnemonic.strip().upper()] += 1
                    continue
                instructions_with_pcode += 1
                for operation_index, operation in enumerate(operations, 1):
                    if not isinstance(operation, dict):
                        raise ValueError(f"{where}: pcode operation {operation_index} must be an object")
                    opcode = operation.get("opcode")
                    if not isinstance(opcode, str) or not opcode.strip():
                        raise ValueError(f"{where}: pcode operation {operation_index} has no opcode")
                    opcode_counts[opcode.strip().upper()] += 1
                    pcode_operation_count += 1

    if not function_count:
        raise ValueError(f"{path}: corpus is empty")

    return {
        "format": FORMAT,
        "source": {
            "format": INPUT_FORMAT,
            "program": next(iter(programs)),
            "sha256": sha256_file(path),
        },
        "functions": {
            "records": function_count,
            "found": found_function_count,
            "missing": function_count - found_function_count,
        },
        "instructions": {
            "total": instruction_count,
            "with_pcode": instructions_with_pcode,
            "without_pcode": sum(no_pcode_mnemonics.values()),
            "without_pcode_mnemonics": dict(sorted(no_pcode_mnemonics.items())),
        },
        "pcode": {
            "operations": pcode_operation_count,
            "unique_opcodes": len(opcode_counts),
            "opcode_counts": dict(sorted(opcode_counts.items())),
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path, help="Ghidra function-instruction JSONL or JSONL.GZ")
    parser.add_argument("--output", type=Path, help="write the compact JSON report here")
    args = parser.parse_args(argv)

    try:
        report = audit(args.corpus)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print("format:", FORMAT)
    print("function records:", report["functions"]["records"])
    print("instructions:", report["instructions"]["total"])
    print("P-code operations:", report["pcode"]["operations"])
    print("unique opcodes:", report["pcode"]["unique_opcodes"])
    print("instructions without P-code:", report["instructions"]["without_pcode_mnemonics"])
    if args.output is not None:
        print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
