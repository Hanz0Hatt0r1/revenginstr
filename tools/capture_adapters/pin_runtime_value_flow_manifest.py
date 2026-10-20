#!/usr/bin/env python3
"""Pin consumer value observations and candidate pairs to a correlation report."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("correlation_report", type=Path)
    parser.add_argument("value_observations", type=Path)
    parser.add_argument("candidates", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    inputs = [args.correlation_report, args.value_observations, args.candidates]
    if args.output.resolve() in {path.resolve() for path in inputs}:
        raise ValueError("output path must not replace an input")
    correlation_raw = args.correlation_report.read_bytes()
    observations_raw = args.value_observations.read_bytes()
    correlation = json.loads(correlation_raw, object_pairs_hook=_unique_object)
    candidates: Any = json.loads(
        args.candidates.read_text(encoding="utf-8"), object_pairs_hook=_unique_object,
    )
    if (
        not isinstance(correlation, dict)
        or correlation.get("format") != "REVENGINSTR.RuntimeStaticCorrelation/1"
    ):
        raise ValueError("expected a RuntimeStaticCorrelation/1 report")
    if not isinstance(correlation.get("capture_id"), str) or not correlation["capture_id"]:
        raise ValueError("correlation report has no capture_id")
    if not isinstance(candidates, list) or not candidates:
        raise ValueError("candidate input must be a non-empty JSON array")
    manifest = {
        "format": "REVENGINSTR.RuntimeValueFlowManifest/1",
        "capture_id": correlation["capture_id"],
        "correlation_report_sha256": hashlib.sha256(correlation_raw).hexdigest(),
        "observations_sha256": hashlib.sha256(observations_raw).hexdigest(),
        "candidates": candidates,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("candidate pairs:", len(candidates))
    print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
