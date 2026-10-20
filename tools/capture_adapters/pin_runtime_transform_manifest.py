#!/usr/bin/env python3
"""Pin a transform replay manifest after runtime/static correlation completes."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

BEHAVIOR_ID = "nevergone-decode-xor-subtract-index-mod-127-u8/v1"


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ValueError(f"{path}: invalid JSON: {error}") from error
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture_metadata", type=Path)
    parser.add_argument("static_correlation", type=Path)
    parser.add_argument("observations", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--candidate-id", default="nevergone-decode-static-recovery")
    args = parser.parse_args()
    metadata = _read_json(args.capture_metadata)
    correlation = _read_json(args.static_correlation)
    if metadata.get("format") != "REVENGINSTR.NevergoneDecodeCaptureMetadata/1":
        raise ValueError("unsupported Nevergone capture metadata")
    if correlation.get("format") != "REVENGINSTR.RuntimeStaticCorrelation/1":
        raise ValueError("expected a RuntimeStaticCorrelation/1 report")
    if correlation.get("capture_id") != metadata.get("capture_id"):
        raise ValueError("capture metadata and correlation report disagree")
    required = ("capture_id", "function_node_id", "source_trace_sha256", "probe_script_sha256")
    if any(not isinstance(metadata.get(key), str) or not metadata[key] for key in required):
        raise ValueError("capture metadata is missing required identity fields")
    manifest = {
        "format": "REVENGINSTR.RuntimeTransformReplayManifest/1",
        "capture_id": metadata["capture_id"],
        "candidate_id": args.candidate_id,
        "behavior_id": BEHAVIOR_ID,
        "expected_function_node_id": metadata["function_node_id"],
        "correlation_report_sha256": _sha256(args.static_correlation),
        "observations_sha256": _sha256(args.observations),
        "source_capture_sha256": metadata["source_trace_sha256"],
        "probe_script_sha256": metadata["probe_script_sha256"],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("capture:", manifest["capture_id"])
    print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
