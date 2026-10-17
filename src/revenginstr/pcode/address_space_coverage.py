#!/usr/bin/env python3
"""Resolve raw P-code LOAD/STORE space IDs against Ghidra language metadata."""
from __future__ import annotations

import argparse
import collections
import gzip
import hashlib
import json
from pathlib import Path
from typing import TextIO

FORMAT = "REVENGINSTR.PcodeAddressSpaceCoverage/1"
CORPUS_FORMAT = "REVENGINSTR.GhidraFunctionInstructions/1"
MANIFEST_FORMAT = "REVENGINSTR.GhidraFunctionInstructionCorpus/1"
SPACES_FORMAT = "REVENGINSTR.GhidraLanguageAddressSpaces/1"


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


def _space_id(offset: object, where: str) -> str:
    if not isinstance(offset, str) or not offset.lower().startswith("0x"):
        raise ValueError(f"{where}: address-space ID is not a hexadecimal constant")
    try:
        value = int(offset, 16)
    except ValueError as exc:
        raise ValueError(f"{where}: invalid address-space ID") from exc
    if value < 0:
        raise ValueError(f"{where}: address-space ID cannot be negative")
    return f"0x{value:x}"


def audit(corpus_path: Path, manifest_path: Path, spaces_path: Path) -> dict:
    manifest = read_json(manifest_path)
    spaces_table = read_json(spaces_path)
    if manifest.get("format") != MANIFEST_FORMAT:
        raise ValueError(f"{manifest_path}: expected {MANIFEST_FORMAT}")
    if spaces_table.get("format") != SPACES_FORMAT:
        raise ValueError(f"{spaces_path}: expected {SPACES_FORMAT}")
    corpus_sha256 = sha256_file(corpus_path)
    manifest_sha256 = manifest.get("output_sha256")
    if not isinstance(manifest_sha256, str) or manifest_sha256.lower() != corpus_sha256:
        raise ValueError("corpus manifest SHA-256 does not match the instruction corpus")

    language_id = manifest.get("language_id")
    if not isinstance(language_id, str) or not language_id:
        raise ValueError("corpus manifest language_id must be a non-empty string")
    if spaces_table.get("language_id") != language_id:
        raise ValueError("address-space table language_id does not match corpus manifest")
    spaces = spaces_table.get("address_spaces")
    if not isinstance(spaces, list):
        raise ValueError("address-space table must contain an address_spaces list")
    names: dict[str, str] = {}
    for item in spaces:
        if not isinstance(item, dict):
            raise ValueError("address-space entry must be an object")
        space_id = _space_id(item.get("space_id"), "address-space table")
        name = item.get("name")
        if not isinstance(name, str) or not name:
            raise ValueError(f"{space_id}: address-space name must be a non-empty string")
        if space_id in names or name in names.values():
            raise ValueError("address-space IDs and names must be unique")
        names[space_id] = name

    program = manifest.get("program")
    if not isinstance(program, str) or not program:
        raise ValueError("corpus manifest program must be a non-empty string")
    function_count = instruction_count = pcode_operation_count = 0
    accesses: collections.Counter[tuple[str, str]] = collections.Counter()
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
            declared_count = row.get("instruction_count")
            if (
                not isinstance(instructions, list)
                or type(declared_count) is not int
                or declared_count != len(instructions)
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
                for op_index, operation in enumerate(instruction["pcode"], 1):
                    if (
                        not isinstance(operation, dict)
                        or not isinstance(operation.get("opcode"), str)
                        or not operation["opcode"].strip()
                    ):
                        raise ValueError(f"{where}: operation {op_index} has no opcode")
                    opcode = operation["opcode"].strip().upper()
                    pcode_operation_count += 1
                    if opcode not in {"LOAD", "STORE"}:
                        continue
                    inputs = operation.get("inputs")
                    if not isinstance(inputs, list) or not inputs or not isinstance(inputs[0], dict):
                        raise ValueError(f"{where}: {opcode} has no address-space ID input")
                    space_node = inputs[0]
                    if space_node.get("space") != "const" or space_node.get("constant") is not True:
                        raise ValueError(f"{where}: {opcode} address-space ID is not constant")
                    accesses[(_space_id(space_node.get("offset"), where), opcode)] += 1

    if not function_count:
        raise ValueError(f"{corpus_path}: corpus is empty")
    exported_count = manifest.get("exported_function_count")
    if type(exported_count) is not int or function_count != exported_count:
        raise ValueError("exported function count does not match corpus manifest")
    manifest_instructions = manifest.get("instruction_count")
    if type(manifest_instructions) is not int or instruction_count != manifest_instructions:
        raise ValueError("instruction count does not match corpus manifest")

    used_ids = sorted({space_id for space_id, _ in accesses}, key=lambda value: int(value, 16))
    mapped = []
    unmapped = []
    for space_id in used_ids:
        counts = {
            opcode.lower() + "_operations": accesses[(space_id, opcode)]
            for opcode in ("LOAD", "STORE")
        }
        row = {"space_id": space_id, **counts, "operations": sum(counts.values())}
        if space_id in names:
            mapped.append({"name": names[space_id], **row})
        else:
            unmapped.append(row)

    return {
        "format": FORMAT,
        "source": {
            "program": program,
            "language_id": language_id,
            "corpus_sha256": corpus_sha256,
            "manifest_sha256": sha256_file(manifest_path),
            "address_spaces_sha256": sha256_file(spaces_path),
        },
        "corpus": {
            "functions": function_count,
            "instructions": instruction_count,
            "pcode_operations": pcode_operation_count,
            "load_operations": sum(count for (_, opcode), count in accesses.items() if opcode == "LOAD"),
            "store_operations": sum(count for (_, opcode), count in accesses.items() if opcode == "STORE"),
        },
        "used_address_spaces": mapped,
        "unmapped_address_spaces": unmapped,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("address_spaces", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = audit(args.corpus, args.manifest, args.address_spaces)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))

    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print("format:", FORMAT)
    print("language:", report["source"]["language_id"])
    print("LOAD operations:", report["corpus"]["load_operations"])
    print("STORE operations:", report["corpus"]["store_operations"])
    print("unmapped used spaces:", len(report["unmapped_address_spaces"]))
    if args.output is not None:
        print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
