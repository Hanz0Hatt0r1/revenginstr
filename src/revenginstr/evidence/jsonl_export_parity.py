"""Compare two JSONL Ghidra exports without retaining record values."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import itertools
import json
import sys
from pathlib import Path
from typing import Any, Iterator

FORMAT = "REVENGINSTR.GhidraJsonlExportParity/1"
_MISSING = object()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _constant(value: str) -> None:
    raise ValueError(f"invalid JSON constant: {value}")


def _records(path: Path) -> Iterator[str]:
    if path.suffix == ".gz":
        source = gzip.open(path, "rt", encoding="utf-8", newline="")
    else:
        source = path.open("r", encoding="utf-8", newline="")
    with source as handle:
        for line_no, line in enumerate(handle, 1):
            try:
                record = json.loads(
                    line,
                    object_pairs_hook=_object,
                    parse_constant=_constant,
                )
                if not isinstance(record, dict):
                    raise ValueError("expected a JSON object")
                yield json.dumps(
                    record,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                )
            except ValueError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSONL record: {exc}") from exc


def compare_exports(left: Path, right: Path) -> dict[str, Any]:
    """Compare JSON objects in order, ignoring object-key order."""
    left_records = iter(_records(left))
    right_records = iter(_records(right))
    first_mismatch: dict[str, Any] | None = None
    left_count = right_count = 0

    for index, (left_record, right_record) in enumerate(
        itertools.zip_longest(left_records, right_records, fillvalue=_MISSING), 1
    ):
        if left_record is not _MISSING:
            left_count += 1
        if right_record is not _MISSING:
            right_count += 1
        if left_record is _MISSING or right_record is _MISSING:
            if first_mismatch is None:
                first_mismatch = {"kind": "record_count", "record_index": index}
        elif left_record != right_record and first_mismatch is None:
            first_mismatch = {"kind": "record", "record_index": index}

    left_hash = _sha256(left)
    right_hash = _sha256(right)
    return {
        "format": FORMAT,
        "left_sha256": left_hash,
        "right_sha256": right_hash,
        "left_records": left_count,
        "right_records": right_count,
        "same_bytes": left_hash == right_hash,
        "same_records": first_mismatch is None,
        "first_mismatch": first_mismatch,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("left", type=Path, help="first UTF-8 JSONL or JSONL.GZ export")
    parser.add_argument("right", type=Path, help="second UTF-8 JSONL or JSONL.GZ export")
    parser.add_argument("--output", type=Path, help="also write the JSON report here")
    args = parser.parse_args(argv)

    try:
        report = compare_exports(args.left, args.right)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"JSONL export parity: {exc}", file=sys.stderr)
        return 2

    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    sys.stdout.write(rendered)
    return 0 if report["same_records"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
