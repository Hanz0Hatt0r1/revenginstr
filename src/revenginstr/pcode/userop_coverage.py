#!/usr/bin/env python3
"""Count language-scoped CALLOTHER userops in a Ghidra function corpus."""
from __future__ import annotations

import argparse
import collections
import gzip
import hashlib
import json
from pathlib import Path
from typing import TextIO

FORMAT = "REVENGINSTR.PcodeUseropCoverage/1"
CORPUS_FORMAT = "REVENGINSTR.GhidraFunctionInstructions/1"
MANIFEST_FORMAT = "REVENGINSTR.GhidraFunctionInstructionCorpus/1"
USEROPS_FORMAT = "REVENGINSTR.GhidraLanguageUserops/1"


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


def read_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def audit(corpus_path: Path, manifest_path: Path, userops_path: Path) -> dict:
    manifest = read_json(manifest_path)
    userop_table = read_json(userops_path)
    if manifest.get("format") != MANIFEST_FORMAT:
        raise ValueError(f"{manifest_path}: expected {MANIFEST_FORMAT}")
    if userop_table.get("format") != USEROPS_FORMAT:
        raise ValueError(f"{userops_path}: expected {USEROPS_FORMAT}")
    corpus_sha256 = sha256_file(corpus_path)
    manifest_sha256 = manifest.get("output_sha256")
    if not isinstance(manifest_sha256, str) or manifest_sha256.lower() != corpus_sha256:
        raise ValueError("corpus manifest SHA-256 does not match the instruction corpus")

    language_id = manifest.get("language_id")
    if not isinstance(language_id, str) or not language_id:
        raise ValueError("corpus manifest language_id must be a non-empty string")
    if userop_table.get("language_id") != language_id:
        raise ValueError("userop table language_id does not match corpus manifest")

    userops = userop_table.get("userops")
    userop_count = userop_table.get("userop_count")
    if not isinstance(userops, list) or type(userop_count) is not int or userop_count != len(userops):
        raise ValueError("userop table count does not match its userops list")
    names: dict[int, str | None] = {}
    for index, item in enumerate(userops):
        if not isinstance(item, dict) or type(item.get("index")) is not int or item["index"] != index:
            raise ValueError("userop table indices must be contiguous from zero")
        name = item.get("name")
        if name is not None and not isinstance(name, str):
            raise ValueError(f"userop {index} name must be a string or null")
        names[index] = name

    program = manifest.get("program")
    if not isinstance(program, str) or not program:
        raise ValueError("corpus manifest program must be a non-empty string")
    function_count = instruction_count = pcode_operation_count = callother_count = 0
    used: collections.Counter[int] = collections.Counter()
    with open_text(corpus_path) as stream:
        for line_no, raw in enumerate(stream, 1):
            if not raw.strip():
                continue
            try:
                row = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{corpus_path}:{line_no}: invalid JSON: {exc.msg}") from exc
            if not isinstance(row, dict) or row.get("format") != CORPUS_FORMAT:
                raise ValueError(f"{corpus_path}:{line_no}: expected {CORPUS_FORMAT} row")
            if row.get("program") != program:
                raise ValueError(f"{corpus_path}:{line_no}: program differs from corpus manifest")
            instructions = row.get("instructions")
            instruction_total = row.get("instruction_count")
            if (
                not isinstance(instructions, list)
                or type(instruction_total) is not int
                or instruction_total != len(instructions)
            ):
                raise ValueError(f"{corpus_path}:{line_no}: instruction_count mismatch")
            found = row.get("found")
            function = row.get("function")
            if not isinstance(found, bool):
                raise ValueError(f"{corpus_path}:{line_no}: found must be a boolean")
            if found and not isinstance(function, dict):
                raise ValueError(f"{corpus_path}:{line_no}: found function requires metadata")
            if not found and (function is not None or instructions):
                raise ValueError(f"{corpus_path}:{line_no}: missing function has metadata or instructions")
            function_count += 1
            instruction_count += len(instructions)
            for instruction_index, instruction in enumerate(instructions, 1):
                where = f"{corpus_path}:{line_no}: instruction {instruction_index}"
                if not isinstance(instruction, dict) or not isinstance(instruction.get("pcode"), list):
                    raise ValueError(f"{where}: expected P-code operation list")
                for operation_index, operation in enumerate(instruction["pcode"], 1):
                    if not isinstance(operation, dict) or not isinstance(operation.get("opcode"), str):
                        raise ValueError(f"{where}: operation {operation_index} has no opcode")
                    pcode_operation_count += 1
                    if operation["opcode"].strip().upper() != "CALLOTHER":
                        continue
                    callother_count += 1
                    inputs = operation.get("inputs")
                    if not isinstance(inputs, list) or not inputs or not isinstance(inputs[0], dict):
                        raise ValueError(f"{where}: CALLOTHER has no userop index input")
                    index_node = inputs[0]
                    if index_node.get("space") != "const" or index_node.get("constant") is not True:
                        raise ValueError(f"{where}: CALLOTHER userop index is not a constant")
                    offset = index_node.get("offset")
                    if not isinstance(offset, str) or not offset.lower().startswith("0x"):
                        raise ValueError(f"{where}: invalid CALLOTHER userop index")
                    try:
                        userop_index = int(offset, 16)
                    except ValueError as exc:
                        raise ValueError(f"{where}: invalid CALLOTHER userop index") from exc
                    if userop_index < 0:
                        raise ValueError(f"{where}: CALLOTHER userop index cannot be negative")
                    used[userop_index] += 1

    if not function_count:
        raise ValueError(f"{corpus_path}: corpus is empty")
    exported_function_count = manifest.get("exported_function_count")
    if type(exported_function_count) is not int or function_count != exported_function_count:
        raise ValueError("exported function count does not match corpus manifest")
    manifest_instruction_count = manifest.get("instruction_count")
    if type(manifest_instruction_count) is not int or instruction_count != manifest_instruction_count:
        raise ValueError("instruction count does not match corpus manifest")
    if sum(used.values()) != callother_count:
        raise ValueError("CALLOTHER userop counts do not cover all operations")

    return {
        "format": FORMAT,
        "source": {
            "program": program,
            "language_id": language_id,
            "corpus_sha256": corpus_sha256,
            "manifest_sha256": sha256_file(manifest_path),
            "userop_table_sha256": sha256_file(userops_path),
        },
        "corpus": {
            "functions": function_count,
            "instructions": instruction_count,
            "pcode_operations": pcode_operation_count,
            "callother_operations": callother_count,
        },
        "used_userops": [
            {"index": index, "name": names.get(index), "uses": count}
            for index, count in sorted(used.items()) if index in names
        ],
        "unmapped_userops": [
            {"index": index, "uses": count}
            for index, count in sorted(used.items()) if index not in names
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("userops", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = audit(args.corpus, args.manifest, args.userops)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print("format:", FORMAT)
    print("language:", report["source"]["language_id"])
    print("CALLOTHER operations:", report["corpus"]["callother_operations"])
    print("used userop indices:", len(report["used_userops"]) + len(report["unmapped_userops"]))
    print("unmapped userop indices:", len(report["unmapped_userops"]))
    if args.output is not None:
        print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
