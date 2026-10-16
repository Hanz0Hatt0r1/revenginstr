#!/usr/bin/env python3
"""Build a scalable indirect-call receiver/type export plan from a trace JSONL."""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

FORMAT = "REVENGINSTR.ReceiverPlan/1"


def read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line_no, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            row = json.loads(raw)
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_no}: expected JSON object")
            yield row


def build_plan(trace: Path, program_filter: str | None = None) -> tuple[list[tuple[str, str]], dict[str, int]]:
    selected: dict[str, str] = {}
    programs: Counter[str] = Counter()
    trace_rows = 0
    for row in read_jsonl(trace):
        trace_rows += 1
        program = row.get("program")
        entry = row.get("source_entry")
        if isinstance(program, str) and program:
            programs[program] += 1
        if program_filter is not None and program != program_filter:
            continue
        if not isinstance(program, str) or not program:
            continue
        if not isinstance(entry, str) or not entry:
            continue
        source_id = f"{program}:{entry}"
        previous = selected.get(source_id)
        if previous is not None and previous != entry:
            raise ValueError(f"conflicting entry for {source_id}")
        selected[source_id] = entry
    if not selected:
        suffix = f" for program {program_filter}" if program_filter else ""
        raise ValueError(f"no trace functions found{suffix}")

    def sort_key(item: tuple[str, str]):
        try:
            return (0, int(item[1], 16), item[0])
        except ValueError:
            return (1, 0, item[1])

    return sorted(selected.items(), key=sort_key), dict(sorted(programs.items()))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--program", help="optional program name filter")
    args = parser.parse_args(argv)

    selected, programs = build_plan(args.trace, args.program)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle, delimiter="\t", lineterminator="\n")
        writer.writerow(["source_id", "source_entry", "expected_calls"])
        for source_id, entry in selected:
            writer.writerow([source_id, entry, ""])

    print("format:", FORMAT)
    print("trace programs:", programs)
    print("selected program:", args.program if args.program else "all")
    print("plan functions:", len(selected))
    print("expected CALLIND counts: discover")
    print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
