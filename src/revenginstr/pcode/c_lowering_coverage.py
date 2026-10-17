#!/usr/bin/env python3
"""Measure whole-function acceptance for the native P-code C lowerer."""
from __future__ import annotations

import argparse
import collections
import gzip
import hashlib
import json
import re
from pathlib import Path
from typing import TextIO

from revenginstr.pcode.c_lowering import (
    CORPUS_FORMAT,
    MANIFEST_FORMAT,
    SPACES_FORMAT,
    PcodeLoweringError,
    compile_function,
)

FORMAT = "REVENGINSTR.PcodeCFunctionLoweringCoverage/1"


def _rejection_reason(error: PcodeLoweringError) -> str:
    message = str(error)
    _, separator, reason = message.partition(": ")
    if not separator:
        reason = message
    return re.sub(r"0x[0-9a-fA-F]+", "0x<offset>", reason)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path: Path) -> dict:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def _open_text(path: Path) -> TextIO:
    if path.suffix.lower() == ".gz":
        return gzip.open(path, "rt", encoding="utf-8")
    return path.open("r", encoding="utf-8")


def audit(corpus_path: Path, manifest_path: Path, spaces_path: Path) -> dict:
    manifest = _read_json(manifest_path)
    spaces = _read_json(spaces_path)
    if manifest.get("format") != MANIFEST_FORMAT:
        raise ValueError(f"{manifest_path}: expected {MANIFEST_FORMAT}")
    if spaces.get("format") != SPACES_FORMAT:
        raise ValueError(f"{spaces_path}: expected {SPACES_FORMAT}")
    corpus_sha256 = _sha256(corpus_path)
    if manifest.get("output_sha256") != corpus_sha256:
        raise ValueError("corpus manifest SHA-256 does not match the instruction corpus")
    program = manifest.get("program")
    language_id = manifest.get("language_id")
    if not isinstance(program, str) or not program:
        raise ValueError("corpus manifest program must be a non-empty string")
    if not isinstance(language_id, str) or not language_id:
        raise ValueError("corpus manifest language_id must be a non-empty string")
    if spaces.get("language_id") != language_id:
        raise ValueError("address-space table language id does not match the corpus manifest")

    records = found = missing = instructions = lowerable = rejected = 0
    lowerable_instructions = lowerable_ops = 0
    rejection_reasons: collections.Counter[str] = collections.Counter()
    with _open_text(corpus_path) as stream:
        for line_no, raw in enumerate(stream, 1):
            if not raw.strip():
                continue
            try:
                row = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{corpus_path}:{line_no}: invalid JSON: {exc.msg}") from exc
            if not isinstance(row, dict) or row.get("format") != CORPUS_FORMAT:
                raise ValueError(f"{corpus_path}:{line_no}: expected {CORPUS_FORMAT}")
            if row.get("program") != program:
                raise ValueError(f"{corpus_path}:{line_no}: program differs from corpus manifest")
            row_instructions = row.get("instructions")
            row_instruction_count = row.get("instruction_count")
            if not isinstance(row_instructions, list) or type(row_instruction_count) is not int:
                raise ValueError(f"{corpus_path}:{line_no}: malformed instruction list or count")
            if row_instruction_count != len(row_instructions):
                raise ValueError(f"{corpus_path}:{line_no}: instruction_count mismatch")
            records += 1
            instructions += row_instruction_count
            found_flag = row.get("found")
            if not isinstance(found_flag, bool):
                raise ValueError(f"{corpus_path}:{line_no}: found must be a boolean")
            if found_flag is False:
                if row.get("function") is not None or row_instructions:
                    raise ValueError(f"{corpus_path}:{line_no}: missing function has metadata or instructions")
                missing += 1
                continue
            found += 1
            try:
                _, operation_count = compile_function(row, spaces)
            except PcodeLoweringError as exc:
                rejected += 1
                rejection_reasons[_rejection_reason(exc)] += 1
            else:
                lowerable += 1
                lowerable_instructions += row_instruction_count
                lowerable_ops += operation_count

    if records == 0:
        raise ValueError(f"{corpus_path}: corpus is empty")
    if type(manifest.get("exported_function_count")) is not int or records != manifest["exported_function_count"]:
        raise ValueError("exported function count does not match the corpus manifest")
    if type(manifest.get("instruction_count")) is not int or instructions != manifest["instruction_count"]:
        raise ValueError("instruction count does not match the corpus manifest")
    return {
        "format": FORMAT,
        "source": {
            "program": program,
            "language_id": language_id,
            "corpus_sha256": corpus_sha256,
            "manifest_sha256": _sha256(manifest_path),
            "address_spaces_sha256": _sha256(spaces_path),
        },
        "functions": {
            "records": records,
            "found": found,
            "missing": missing,
            "fully_lowerable": lowerable,
            "rejected": rejected,
        },
        "instructions": {
            "total": instructions,
            "in_fully_lowerable_functions": lowerable_instructions,
        },
        "pcode_operations": {
            "in_fully_lowerable_functions": lowerable_ops,
        },
        "rejection_reasons": [
            {"reason": reason, "functions": count}
            for reason, count in sorted(rejection_reasons.items(), key=lambda item: (-item[1], item[0]))
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("address_spaces", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = audit(args.corpus, args.manifest, args.address_spaces)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("function records:", report["functions"]["records"])
    print("fully lowerable:", report["functions"]["fully_lowerable"])
    print("rejected:", report["functions"]["rejected"])
    print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
