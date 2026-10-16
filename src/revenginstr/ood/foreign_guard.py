#!/usr/bin/env python3
"""Apply a monotone safety floor to foreign-project classifier output.

The guard never promotes an action. It only downgrades `accept` to `review` when
cross-project family similarity or contrast margin are below fixed diagnostic
floors. It does not use target-project labels and therefore is not a correctness
calibrator.
"""
from __future__ import annotations

import argparse
import collections
import json
import math
from pathlib import Path
from typing import Any

FORMAT = "REVENGINSTR.ForeignGuard/1"


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


def _numeric(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    value = float(value)
    return value if math.isfinite(value) else None


def guarded_row(row: dict[str, Any], similarity_floor: float, contrast_floor: float) -> dict[str, Any]:
    out = dict(row)
    base_action = str(row.get("action"))
    out["base_action"] = row.get("base_action", base_action)
    out["foreign_guard_format"] = FORMAT
    out["foreign_guard_changed"] = False
    out["foreign_guard_reasons"] = []

    class_similarity_floor = _numeric(row.get("ood_accept_threshold"))
    class_contrast_floor = _numeric(row.get("contrast_accept_threshold"))
    similarity_floor = max(similarity_floor, class_similarity_floor or 0.0)
    contrast_floor = max(contrast_floor, class_contrast_floor or 0.0)
    out["foreign_similarity_floor"] = similarity_floor
    out["foreign_contrast_floor"] = contrast_floor

    similarity = _numeric(row.get("family_similarity"))
    contrast = _numeric(row.get("contrast_margin"))
    similarity_pass = similarity is not None and similarity >= similarity_floor
    contrast_pass = contrast is not None and contrast >= contrast_floor
    out["foreign_similarity_pass"] = similarity_pass
    out["foreign_contrast_pass"] = contrast_pass
    out["foreign_guard_pass"] = similarity_pass and contrast_pass

    if base_action != "accept":
        return out

    reasons: list[str] = []
    if similarity is None:
        reasons.append("missing_family_similarity")
    elif float(similarity) < similarity_floor:
        reasons.append("family_similarity_below_floor")
    if contrast is None:
        reasons.append("missing_contrast_margin")
    elif float(contrast) < contrast_floor:
        reasons.append("contrast_margin_below_floor")

    if reasons:
        out["action"] = "review"
        out["foreign_guard_changed"] = True
        out["foreign_guard_reasons"] = reasons
    return out


def apply_guard(rows: list[dict[str, Any]], similarity_floor: float, contrast_floor: float) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    guarded = [guarded_row(row, similarity_floor, contrast_floor) for row in rows]
    base_actions = collections.Counter(str(row.get("action")) for row in rows)
    actions = collections.Counter(str(row.get("action")) for row in guarded)
    reasons: collections.Counter[str] = collections.Counter()
    changed = 0
    promotions = 0
    for before, after in zip(rows, guarded):
        if after.get("foreign_guard_changed"):
            changed += 1
            reasons.update(str(reason) for reason in after.get("foreign_guard_reasons", []))
        if before.get("action") in {"review", "escalate"} and after.get("action") == "accept":
            promotions += 1
    base_accept = base_actions.get("accept", 0)
    accept = actions.get("accept", 0)
    summary = {
        "format": FORMAT,
        "rows": len(rows),
        "similarity_floor": similarity_floor,
        "contrast_floor": contrast_floor,
        "base_actions": dict(sorted(base_actions.items())),
        "actions": dict(sorted(actions.items())),
        "changed_accepts": changed,
        "changed_fraction": changed / len(rows) if rows else 0.0,
        "accept_retention": accept / base_accept if base_accept else None,
        "promotions": promotions,
        "reasons": dict(sorted(reasons.items())),
        "semantic_labels_used": False,
    }
    return guarded, summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--summary", type=Path)
    parser.add_argument("--similarity-floor", type=float, default=0.70)
    parser.add_argument("--contrast-floor", type=float, default=0.05)
    args = parser.parse_args(argv)

    rows = read_jsonl(args.input)
    guarded, summary = apply_guard(rows, args.similarity_floor, args.contrast_floor)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for row in guarded:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    if args.summary is not None:
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    print("format:", FORMAT)
    print("rows:", summary["rows"])
    print("base actions:", summary["base_actions"])
    print("actions:", summary["actions"])
    print("changed accepts:", summary["changed_accepts"])
    print("accept retention:", summary["accept_retention"])
    print("promotions:", summary["promotions"])
    print("reasons:", summary["reasons"])
    print("output:", args.output)
    return 0 if summary["promotions"] == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
