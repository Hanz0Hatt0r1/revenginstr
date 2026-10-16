#!/usr/bin/env python3
"""Audit a REVENGINSTR portable high-P-code corpus and optional classifications."""
from __future__ import annotations

import argparse
import collections
import json
import math
import statistics
from pathlib import Path
from typing import Any, Iterable

FORMAT = "REVENGINSTR.PcodeAudit/1"


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            row = json.loads(raw)
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_no}: expected object")
            rows.append(row)
    return rows


def header_value(text: str, name: str) -> str | None:
    prefix = name + "="
    for line in text.splitlines():
        if line.startswith(prefix):
            return line[len(prefix):]
    return None


def quantiles(values: Iterable[float]) -> dict[str, float | None]:
    data = sorted(float(value) for value in values if math.isfinite(float(value)))
    if not data:
        return {"min": None, "median": None, "p90": None, "max": None}

    def pick(q: float) -> float:
        index = min(len(data) - 1, max(0, round((len(data) - 1) * q)))
        return data[index]

    return {
        "min": data[0],
        "median": statistics.median(data),
        "p90": pick(0.90),
        "max": data[-1],
    }


def corpus_audit(rows: list[dict[str, Any]]) -> dict[str, Any]:
    formats: collections.Counter[str] = collections.Counter()
    statuses: collections.Counter[str] = collections.Counter()
    arch: collections.Counter[str] = collections.Counter()
    endian: collections.Counter[str] = collections.Counter()
    ptr: collections.Counter[str] = collections.Counter()
    callconv: collections.Counter[str] = collections.Counter()
    leakage: list[dict[str, Any]] = []
    emitted: list[int] = []
    truncated = 0

    for index, row in enumerate(rows, 1):
        formats[str(row.get("format"))] += 1
        status = str(row.get("decompile_status"))
        statuses[status] += 1
        if status != "ok":
            continue
        text = row.get("model_text")
        if not isinstance(text, str) or not text:
            leakage.append({"row": index, "reason": "missing_model_text"})
            continue
        arch[str(header_value(text, "ARCH"))] += 1
        endian[str(header_value(text, "ENDIAN"))] += 1
        ptr[str(header_value(text, "PTR_SIZE"))] += 1
        callconv[str(header_value(text, "CALLCONV"))] += 1
        for label in ("source_entry", "source_name", "program"):
            value = row.get(label)
            if isinstance(value, str) and value and value in text:
                leakage.append({"row": index, "reason": f"{label}_leaked"})
        metrics = row.get("metrics") if isinstance(row.get("metrics"), dict) else {}
        emitted_ops = metrics.get("emitted_ops")
        if isinstance(emitted_ops, int):
            emitted.append(emitted_ops)
            if emitted_ops > 256:
                leakage.append({"row": index, "reason": "emitted_ops_gt_256"})
        if bool(metrics.get("truncated")):
            truncated += 1

    ok = statuses.get("ok", 0)
    return {
        "rows": len(rows),
        "formats": dict(sorted(formats.items())),
        "statuses": dict(sorted(statuses.items())),
        "architecture": dict(sorted(arch.items())),
        "endian": dict(sorted(endian.items())),
        "pointer_size": dict(sorted(ptr.items())),
        "calling_convention": dict(sorted(callconv.items())),
        "truncated": truncated,
        "truncated_fraction": truncated / ok if ok else 0.0,
        "emitted_ops": quantiles(emitted),
        "leakage_findings": leakage,
        "portable_contract_pass": bool(ok) and not leakage,
    }


def transfer_audit(rows: list[dict[str, Any]]) -> dict[str, Any]:
    predictions = collections.Counter(str(row.get("prediction")) for row in rows)
    actions = collections.Counter(str(row.get("action")) for row in rows)
    base_actions = collections.Counter(str(row.get("base_action")) for row in rows if row.get("base_action") is not None)
    confidence = [float(row["confidence"]) for row in rows if isinstance(row.get("confidence"), (int, float))]
    raw_confidence = [float(row["raw_confidence"]) for row in rows if isinstance(row.get("raw_confidence"), (int, float))]
    similarity = [float(row["family_similarity"]) for row in rows if isinstance(row.get("family_similarity"), (int, float))]
    contrast = [float(row["contrast_margin"]) for row in rows if isinstance(row.get("contrast_margin"), (int, float))]
    promotions = sum(
        1
        for row in rows
        if row.get("base_action") in {"review", "escalate"} and row.get("action") == "accept"
    )
    changed = sum(row.get("base_action") is not None and row.get("base_action") != row.get("action") for row in rows)
    accept = actions.get("accept", 0)
    base_accept = base_actions.get("accept", 0)
    return {
        "rows": len(rows),
        "predictions": dict(sorted(predictions.items())),
        "base_actions": dict(sorted(base_actions.items())),
        "actions": dict(sorted(actions.items())),
        "base_accept_fraction": base_accept / len(rows) if rows and base_actions else None,
        "accept_fraction": accept / len(rows) if rows else 0.0,
        "accept_retention": accept / base_accept if base_accept else None,
        "changed_actions": changed,
        "promotions": promotions,
        "confidence": quantiles(confidence),
        "raw_confidence": quantiles(raw_confidence),
        "family_similarity": quantiles(similarity),
        "contrast_margin": quantiles(contrast),
        "semantic_labels_available": False,
        "interpretation": "Cross-project/OOD probe only; accept is not semantic correctness without target-project labels.",
    }


def build_report(corpus_rows: list[dict[str, Any]], classified_rows: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    report: dict[str, Any] = {
        "format": FORMAT,
        "corpus": corpus_audit(corpus_rows),
        "transfer": None,
    }
    if classified_rows is not None:
        report["transfer"] = transfer_audit(classified_rows)
        if len(classified_rows) != report["corpus"]["statuses"].get("ok", 0):
            report["transfer"]["row_count_warning"] = "classified rows differ from successful corpus rows"
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    parser.add_argument("--classified", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    corpus = read_jsonl(args.corpus)
    if not corpus:
        raise SystemExit("corpus is empty")
    classified = read_jsonl(args.classified) if args.classified is not None else None
    report = build_report(corpus, classified)

    if args.output is not None:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    corpus_report = report["corpus"]
    print("format:", FORMAT)
    print("rows:", corpus_report["rows"])
    print("statuses:", corpus_report["statuses"])
    print("architecture:", corpus_report["architecture"])
    print("pointer size:", corpus_report["pointer_size"])
    print("portable contract pass:", corpus_report["portable_contract_pass"])
    print("leakage findings:", len(corpus_report["leakage_findings"]))
    if report["transfer"] is not None:
        transfer = report["transfer"]
        print("predictions:", transfer["predictions"])
        if transfer["base_actions"]:
            print("base actions:", transfer["base_actions"])
            print("base accept fraction:", transfer["base_accept_fraction"])
        print("actions:", transfer["actions"])
        print("accept fraction:", round(transfer["accept_fraction"], 6))
        print("accept retention:", transfer["accept_retention"])
        print("promotions:", transfer["promotions"])
        print("family similarity:", transfer["family_similarity"])
        print("contrast margin:", transfer["contrast_margin"])
        print("semantic labels available:", transfer["semantic_labels_available"])
    if args.output is not None:
        print("output:", args.output)
    return 0 if corpus_report["portable_contract_pass"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
