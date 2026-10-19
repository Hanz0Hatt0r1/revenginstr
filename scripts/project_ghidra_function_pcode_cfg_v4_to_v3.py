#!/usr/bin/env python3
"""Project CFG/4 JSONL into CFG/3 by dropping only indirect-effect links."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path
from typing import Any


FORMAT_V4 = "REVENGINSTR.GhidraFunctionPcodeCFG/4"
FORMAT_V3 = "REVENGINSTR.GhidraFunctionPcodeCFG/3"


def project_records(source: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(source.read_text(encoding="utf-8").splitlines(), 1):
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{source}:{line_number}: invalid JSON") from exc
        if not isinstance(record, dict) or record.get("format") != FORMAT_V4:
            raise ValueError(f"{source}:{line_number}: expected {FORMAT_V4}")
        blocks = record.get("blocks")
        if not isinstance(blocks, list):
            raise ValueError(f"{source}:{line_number}: blocks must be an array")
        for block in blocks:
            if not isinstance(block, dict) or not isinstance(block.get("operations"), list):
                raise ValueError(f"{source}:{line_number}: malformed block")
            for operation in block["operations"]:
                if not isinstance(operation, dict) or "indirect_effect_link" not in operation:
                    raise ValueError(f"{source}:{line_number}: malformed CFG/4 operation")
                operation.pop("indirect_effect_link")
        record["format"] = FORMAT_V3
        records.append(record)
    if not records:
        raise ValueError(f"{source}: no CFG records")
    return records


def write_jsonl_atomic(output: Path, records: list[dict[str, Any]]) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=output.parent, prefix=f".{output.name}.", delete=False
        ) as handle:
            temporary_path = Path(handle.name)
            for record in records:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
        os.replace(temporary_path, output)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="GhidraFunctionPcodeCFG/4 JSONL")
    parser.add_argument("output", type=Path, help="GhidraFunctionPcodeCFG/3 JSONL")
    args = parser.parse_args(argv)
    records = project_records(args.input)
    write_jsonl_atomic(args.output, records)
    print("CFG records:", len(records))
    print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
