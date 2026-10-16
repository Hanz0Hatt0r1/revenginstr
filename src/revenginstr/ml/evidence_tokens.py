"""Leakage-safe numeric evidence tokenization for sparse classifiers."""
from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Any

from revenginstr.evidence.structural import structural_metrics

EVIDENCE_FORMAT = "REVENGINSTR.Evidence/1"


def safe_key(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]+", "_", value).strip("_") or "feature"


def bucket_number(value: float) -> str:
    value = float(value)
    if not math.isfinite(value):
        return "nonfinite"
    if value == 0.0:
        return "0"
    if -1.0 <= value <= 1.0 and not math.isclose(value, round(value), abs_tol=1e-12):
        return f"ratio_{int(round(value * 10.0)):+d}"
    sign = "neg_" if value < 0 else ""
    magnitude = abs(value)
    if magnitude < 1:
        return sign + "lt1"
    lower = upper = 1
    while upper < magnitude and upper < (1 << 20):
        lower = upper + 1
        upper = (upper << 1) + 1
    if upper >= (1 << 20) and magnitude > upper:
        return sign + "1048576_plus"
    if lower == upper:
        return sign + str(lower)
    return f"{sign}{lower}_{upper}"


def load_evidence(path: Path | None) -> dict[str, dict[str, float]]:
    if path is None:
        return {}
    result: dict[str, dict[str, float]] = {}
    with path.open("r", encoding="utf-8") as handle:
        for line_no, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            row = json.loads(raw)
            if not isinstance(row, dict) or row.get("format") != EVIDENCE_FORMAT:
                raise ValueError(f"{path}:{line_no}: expected {EVIDENCE_FORMAT}")
            record_id = row.get("id")
            features = row.get("features")
            if not isinstance(record_id, str) or not record_id:
                raise ValueError(f"{path}:{line_no}: missing id")
            if record_id in result:
                raise ValueError(f"{path}:{line_no}: duplicate id {record_id}")
            if not isinstance(features, dict):
                raise ValueError(f"{path}:{line_no}: features must be an object")
            clean: dict[str, float] = {}
            for key, value in features.items():
                if not isinstance(key, str) or not key:
                    continue
                if isinstance(value, bool):
                    clean[key] = float(value)
                elif isinstance(value, (int, float)) and math.isfinite(float(value)):
                    clean[key] = float(value)
            result[record_id] = clean
    return result


def evidence_features(text: str, external: dict[str, float] | None = None) -> dict[str, float]:
    features: dict[str, float] = {
        f"structural.{key}": float(value)
        for key, value in structural_metrics(text).items()
        if isinstance(value, (int, float)) and math.isfinite(float(value))
    }
    if external:
        for key, value in external.items():
            if isinstance(key, str) and key and isinstance(value, (int, float)) and math.isfinite(float(value)):
                features[f"external.{key}"] = float(value)
    return features


def evidence_tokens(text: str, external: dict[str, float] | None = None) -> list[str]:
    return [
        f"EV|{safe_key(key)}|{bucket_number(value)}"
        for key, value in sorted(evidence_features(text, external).items())
    ]


def augment_text(text: str, external: dict[str, float] | None = None) -> tuple[str, int]:
    tokens = evidence_tokens(text, external)
    if not tokens:
        return text, 0
    return text + "\n" + " ".join(tokens), len(tokens)
