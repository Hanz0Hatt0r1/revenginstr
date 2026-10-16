#!/usr/bin/env python3
"""Extract project-neutral callgraph metrics from full-index TSV exports."""
from __future__ import annotations

import argparse
import csv
import gzip
import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable

FORMAT = "REVENGINSTR.CallGraphMetrics/1"


def read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line_no, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            row = json.loads(raw)
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_no}: expected JSON object")
            yield row


def open_tsv(path: Path):
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", newline="")
    return path.open("r", encoding="utf-8", newline="")


def identity(row: dict[str, Any], line_no: int) -> tuple[str, str]:
    record_id = row.get("id")
    program = row.get("program")
    entry = row.get("source_entry")
    if isinstance(record_id, str) and record_id:
        if not isinstance(entry, str) or not entry:
            raise ValueError(f"input row {line_no} has id but no source_entry")
        return record_id, entry
    if isinstance(program, str) and program and isinstance(entry, str) and entry:
        return f"{program}:{entry}", entry
    raise ValueError(f"input row {line_no} has no usable identity")


def corpus_call_counts(row: dict[str, Any]) -> tuple[int | None, int | None]:
    metrics = row.get("metrics")
    if not isinstance(metrics, dict):
        return None, None
    calls = metrics.get("calls")
    indirect = metrics.get("indirect_calls")
    if not isinstance(calls, int) or calls < 0:
        calls = None
    if not isinstance(indirect, int) or indirect < 0:
        indirect = None
    return calls, indirect


def load_functions(path: Path) -> dict[str, bool]:
    functions: dict[str, bool] = {}
    with open_tsv(path) as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        required = {"entry", "is_external"}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError(f"{path}: expected columns {sorted(required)}")
        for row in reader:
            functions[row["entry"]] = row["is_external"].strip().lower() == "true"
    return functions


def load_calls(path: Path):
    outgoing_sites: dict[str, list[tuple[str, str]]] = defaultdict(list)
    incoming: dict[str, set[str]] = defaultdict(set)
    with open_tsv(path) as handle:
        reader = csv.DictReader(handle, delimiter="\t")
        required = {"caller_entry", "call_site", "callee_entry"}
        if not required.issubset(reader.fieldnames or []):
            raise ValueError(f"{path}: expected columns {sorted(required)}")
        for row in reader:
            caller = row["caller_entry"]
            call_site = row["call_site"]
            callee = row["callee_entry"]
            outgoing_sites[caller].append((call_site, callee))
            incoming[callee].add(caller)
    return outgoing_sites, incoming


def metrics_for(entry: str, *, functions: dict[str, bool], outgoing_sites, incoming,
                corpus_calls: int | None, corpus_indirect_calls: int | None) -> dict[str, Any]:
    sites = outgoing_sites.get(entry, [])
    distinct_callees = {callee for _, callee in sites}
    callers = incoming.get(entry, set())
    internal_callees = {callee for callee in distinct_callees if functions.get(callee) is False}
    external_callees = {callee for callee in distinct_callees if functions.get(callee) is True}
    unknown_callees = distinct_callees - internal_callees - external_callees
    internal_sites = sum(1 for _, callee in sites if functions.get(callee) is False)
    external_sites = sum(1 for _, callee in sites if functions.get(callee) is True)
    unknown_sites = len(sites) - internal_sites - external_sites

    total_calls = corpus_calls
    indirect_calls = corpus_indirect_calls
    if total_calls is None:
        direct_calls = None
        resolved_ratio = None
        unknown_ratio = None
    else:
        indirect_calls = indirect_calls if indirect_calls is not None else 0
        direct_calls = max(0, total_calls - indirect_calls)
        resolved_ratio = min(1.0, len(sites) / total_calls) if total_calls else 1.0
        unknown_ratio = max(0.0, 1.0 - resolved_ratio)

    return {
        "fan_in": len(callers),
        "fan_out": len(distinct_callees),
        "resolved_call_site_count": len(sites),
        "distinct_callee_count": len(distinct_callees),
        "distinct_caller_count": len(callers),
        "internal_call_site_count": internal_sites,
        "external_call_site_count": external_sites,
        "unknown_target_call_site_count": unknown_sites,
        "internal_callee_count": len(internal_callees),
        "external_callee_count": len(external_callees),
        "unknown_callee_count": len(unknown_callees),
        "corpus_call_count": total_calls,
        "corpus_indirect_call_count": indirect_calls,
        "corpus_direct_call_count": direct_calls,
        "resolved_call_ratio_proxy": resolved_ratio,
        "unknown_call_ratio_proxy": unknown_ratio,
    }


def extract(corpus: Path, functions_tsv: Path, calls_tsv: Path) -> list[dict[str, Any]]:
    functions = load_functions(functions_tsv)
    outgoing_sites, incoming = load_calls(calls_tsv)
    rows = list(read_jsonl(corpus))
    if not rows:
        raise ValueError("input is empty")
    output: list[dict[str, Any]] = []
    seen: set[str] = set()
    for line_no, row in enumerate(rows, 1):
        record_id, entry = identity(row, line_no)
        if record_id in seen:
            raise ValueError(f"duplicate id: {record_id}")
        calls, indirect = corpus_call_counts(row)
        output.append({
            "format": FORMAT,
            "id": record_id,
            "source_entry": entry,
            "metrics": metrics_for(entry, functions=functions, outgoing_sites=outgoing_sites,
                                   incoming=incoming, corpus_calls=calls,
                                   corpus_indirect_calls=indirect),
        })
        seen.add(record_id)
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    parser.add_argument("functions_tsv", type=Path)
    parser.add_argument("calls_tsv", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    rows = extract(args.corpus, args.functions_tsv, args.calls_tsv)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    print("format:", FORMAT)
    print("functions:", len(rows))
    print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
