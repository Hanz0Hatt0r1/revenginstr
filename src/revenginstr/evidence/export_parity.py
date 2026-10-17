"""Compare two decoded Ghidra TSV exports and emit a compact parity record."""
from __future__ import annotations

import argparse
import csv
import hashlib
import itertools
import json
import sys
from pathlib import Path
from typing import Any

FORMAT = "REVENGINSTR.GhidraExportParity/1"
_MISSING = object()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _rows(path: Path):
    with path.open("r", encoding="utf-8", newline="") as handle:
        yield from csv.reader(handle, delimiter="\t", strict=True)


def compare_exports(left: Path, right: Path) -> dict[str, Any]:
    """Compare headers and rows in order without retaining export contents."""
    left_rows = iter(_rows(left))
    right_rows = iter(_rows(right))
    left_header = next(left_rows, None)
    right_header = next(right_rows, None)
    if left_header is None or right_header is None:
        raise ValueError("both exports must contain a TSV header")

    first_mismatch: dict[str, Any] | None = None
    if left_header != right_header:
        first_mismatch = {"kind": "header", "record_index": 0}

    left_count = right_count = 0
    for index, (left_row, right_row) in enumerate(
        itertools.zip_longest(left_rows, right_rows, fillvalue=_MISSING), 1
    ):
        if left_row is not _MISSING:
            left_count += 1
        if right_row is not _MISSING:
            right_count += 1
        if left_row is _MISSING or right_row is _MISSING:
            if first_mismatch is None:
                first_mismatch = {"kind": "row_count", "record_index": index}
            continue
        if left_row == right_row:
            continue
        if first_mismatch is None:
            first_mismatch = {"kind": "row", "record_index": index}

    left_hash = _sha256(left)
    right_hash = _sha256(right)
    return {
        "format": FORMAT,
        "left_sha256": left_hash,
        "right_sha256": right_hash,
        "left_rows": left_count,
        "right_rows": right_count,
        "same_bytes": left_hash == right_hash,
        "same_records": first_mismatch is None,
        "first_mismatch": first_mismatch,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("left", type=Path, help="first UTF-8 TSV export")
    parser.add_argument("right", type=Path, help="second UTF-8 TSV export")
    parser.add_argument("--output", type=Path, help="also write the JSON report here")
    args = parser.parse_args(argv)

    try:
        report = compare_exports(args.left, args.right)
    except (OSError, UnicodeError, csv.Error, ValueError) as exc:
        print(f"export parity: {exc}", file=sys.stderr)
        return 2

    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    sys.stdout.write(rendered)
    return 0 if report["same_records"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
