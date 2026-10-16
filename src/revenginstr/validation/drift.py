"""Audit unlabeled distribution shift between reference and frozen classifications.

The audit compares prediction/action distributions, confidence/OOD features,
accept-router intervention rates and evidence-key coverage. It is diagnostic only:
it never converts an unlabeled frozen set into a semantic accuracy estimate.

Consumers with historical routing lineage may overlay a retained base-action file
by id. This keeps experiment-specific action names/versions outside the generic
core while allowing exact drift parity against old deployment baselines.
"""
from __future__ import annotations

import argparse
import json
import math
import statistics
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from revenginstr.ml.evidence_tokens import load_evidence
from . import DRIFT_AUDIT_FORMAT

CORE_NUMERIC = (
    "confidence",
    "raw_confidence",
    "family_similarity",
    "competing_similarity",
    "contrast_margin",
    "max_probability",
    "top2_gap",
    "entropy",
)
DEFAULT_CORE_EVIDENCE = (
    "has_callgraph",
    "has_receiver_types",
    "has_receiver_inference",
)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            row = json.loads(raw)
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_no}: expected JSON object")
            rows.append(row)
    return rows


def overlay_reference_base_actions(
    reference_rows: list[dict[str, Any]],
    action_rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Overlay consumer-retained base actions by id without changing predictions.

    Companion rows may expose either ``base_action`` or ``action``. The companion
    population must match the reference population exactly; drift parity fails
    closed instead of silently dropping historical routing rows.
    """
    by_id: dict[str, str] = {}
    for row in action_rows:
        record_id = row.get("id")
        action = row.get("base_action", row.get("action"))
        if not isinstance(record_id, str) or not record_id:
            raise ValueError("reference base-action row missing id")
        if not isinstance(action, str) or not action:
            raise ValueError(f"reference base-action row {record_id}: missing base_action/action")
        if record_id in by_id:
            raise ValueError(f"duplicate reference base-action id: {record_id}")
        by_id[record_id] = action

    reference_ids: set[str] = set()
    output: list[dict[str, Any]] = []
    for row in reference_rows:
        record_id = row.get("id")
        if not isinstance(record_id, str) or not record_id:
            raise ValueError("reference classified row missing id")
        if record_id in reference_ids:
            raise ValueError(f"duplicate reference classified id: {record_id}")
        reference_ids.add(record_id)
        if record_id not in by_id:
            raise ValueError(f"reference base-action companion missing id: {record_id}")
        payload = dict(row)
        payload["base_action"] = by_id[record_id]
        output.append(payload)

    extras = sorted(set(by_id) - reference_ids)
    if extras:
        raise ValueError(f"reference base-action companion has {len(extras)} extra ids; first={extras[0]}")
    return output


def quantile(values: list[float], q: float) -> float | None:
    clean = sorted(value for value in values if math.isfinite(value))
    if not clean:
        return None
    if len(clean) == 1:
        return clean[0]
    position = (len(clean) - 1) * q
    lower = int(math.floor(position))
    upper = int(math.ceil(position))
    if lower == upper:
        return clean[lower]
    weight = position - lower
    return clean[lower] * (1.0 - weight) + clean[upper] * weight


def numeric_summary(values: Iterable[float]) -> dict[str, float | int | None]:
    clean = [float(value) for value in values if math.isfinite(float(value))]
    if not clean:
        return {"count": 0, "mean": None, "p10": None, "median": None, "p90": None, "iqr": None}
    p25 = quantile(clean, 0.25)
    p75 = quantile(clean, 0.75)
    return {
        "count": len(clean),
        "mean": float(statistics.fmean(clean)),
        "p10": quantile(clean, 0.10),
        "median": quantile(clean, 0.50),
        "p90": quantile(clean, 0.90),
        "iqr": float(p75 - p25) if p25 is not None and p75 is not None else None,
    }


def probability_features(row: dict[str, Any]) -> tuple[float, float, float]:
    payload = row.get("probabilities")
    if not isinstance(payload, dict):
        return 0.0, 0.0, 0.0
    values = [
        float(value)
        for value in payload.values()
        if isinstance(value, (int, float)) and math.isfinite(float(value)) and float(value) >= 0.0
    ]
    if not values:
        return 0.0, 0.0, 0.0
    values.sort(reverse=True)
    maximum = values[0]
    gap = maximum - values[1] if len(values) > 1 else maximum
    entropy = -sum(value * math.log(value) for value in values if value > 0.0)
    return maximum, gap, entropy


def numeric_value(row: dict[str, Any], key: str) -> float:
    if key in {"max_probability", "top2_gap", "entropy"}:
        maximum, gap, entropy = probability_features(row)
        return {"max_probability": maximum, "top2_gap": gap, "entropy": entropy}[key]
    value = row.get(key, 0.0)
    if isinstance(value, (int, float)) and math.isfinite(float(value)):
        return float(value)
    return 0.0


def categorical_distribution(values: Iterable[str]) -> dict[str, float]:
    counts = Counter(str(value) for value in values)
    total = sum(counts.values())
    if not total:
        return {}
    return {key: count / total for key, count in sorted(counts.items())}


def js_divergence_bits(left: dict[str, float], right: dict[str, float]) -> float:
    result = 0.0
    for key in sorted(set(left) | set(right)):
        p = float(left.get(key, 0.0))
        q = float(right.get(key, 0.0))
        midpoint = (p + q) / 2.0
        if p > 0.0:
            result += 0.5 * p * math.log2(p / midpoint)
        if q > 0.0:
            result += 0.5 * q * math.log2(q / midpoint)
    return result


def distribution_payload(reference: Iterable[str], frozen: Iterable[str]) -> dict[str, Any]:
    ref = categorical_distribution(reference)
    new = categorical_distribution(frozen)
    return {
        "reference": ref,
        "frozen": new,
        "js_divergence_bits": js_divergence_bits(ref, new),
    }


def numeric_shift(reference_rows: list[dict[str, Any]], frozen_rows: list[dict[str, Any]], key: str) -> dict[str, Any]:
    reference = numeric_summary(numeric_value(row, key) for row in reference_rows)
    frozen = numeric_summary(numeric_value(row, key) for row in frozen_rows)
    ref_median = reference["median"]
    frozen_median = frozen["median"]
    ref_iqr = reference["iqr"]
    median_delta = None
    robust_shift = None
    if ref_median is not None and frozen_median is not None:
        median_delta = float(frozen_median - ref_median)
        if ref_iqr is not None and abs(float(ref_iqr)) > 1e-12:
            robust_shift = median_delta / float(ref_iqr)
    return {
        "reference": reference,
        "frozen": frozen,
        "median_delta": median_delta,
        "robust_shift_iqr": robust_shift,
    }


def evidence_coverage(evidence: dict[str, dict[str, float]], keys: Iterable[str]) -> dict[str, float]:
    total = max(1, len(evidence))
    return {
        key: sum(key in features for features in evidence.values()) / total
        for key in keys
    }


def _base_action(row: dict[str, Any]) -> str:
    value = row.get("base_action")
    return str(value if value is not None else row.get("action"))


def _actual_router_stats(rows: list[dict[str, Any]]) -> tuple[int, int] | None:
    if not any("accept_router_changed" in row for row in rows):
        return None
    legacy_accept = sum(_base_action(row) == "accept" for row in rows)
    changed = sum(bool(row.get("accept_router_changed")) for row in rows)
    return legacy_accept, changed


def _manifest_router_stats(manifest: dict[str, Any] | None) -> tuple[int, int] | None:
    if not manifest:
        return None
    calibration = manifest.get("calibration")
    if not isinstance(calibration, dict):
        return None
    legacy = calibration.get("legacy_accept_examples")
    kept = calibration.get("kept_examples")
    if not isinstance(legacy, int) or not isinstance(kept, int):
        return None
    return legacy, max(0, legacy - kept)


def _routed_reference_actions(
    reference_rows: list[dict[str, Any]],
    router_stats: tuple[int, int] | None,
    *,
    actual_router_stats: tuple[int, int] | None,
) -> list[str]:
    if actual_router_stats is not None:
        return [str(row.get("action")) for row in reference_rows]
    if router_stats is None:
        return [str(row.get("action")) for row in reference_rows]
    legacy_accept, changed = router_stats
    base_review = sum(_base_action(row) == "review" for row in reference_rows)
    base_escalate = sum(_base_action(row) == "escalate" for row in reference_rows)
    return (
        ["accept"] * max(0, legacy_accept - changed)
        + ["review"] * base_review
        + ["escalate"] * (base_escalate + changed)
    )


def severity(summary: dict[str, Any]) -> dict[str, Any]:
    prediction_js = float(summary["categorical_shift"]["prediction"]["js_divergence_bits"])
    base_action_js = float(summary["categorical_shift"]["base_action"]["js_divergence_bits"])
    robust = [
        abs(float(payload["robust_shift_iqr"]))
        for payload in summary["numeric_shift_all"].values()
        if payload.get("robust_shift_iqr") is not None
    ]
    max_robust = max(robust, default=0.0)
    core = summary["evidence_shift"]["core"]
    max_core_drop = max(
        (max(0.0, float(payload["reference"]) - float(payload["frozen"])) for payload in core.values()),
        default=0.0,
    )
    ratio = summary["router_intervention"].get("accept_change_rate_ratio")
    ratio_value = float(ratio) if isinstance(ratio, (int, float)) and math.isfinite(float(ratio)) else 0.0
    if prediction_js >= 0.10 or base_action_js >= 0.10 or max_robust >= 1.0 or max_core_drop >= 0.15:
        level = "high"
    elif prediction_js >= 0.03 or base_action_js >= 0.03 or max_robust >= 0.5 or max_core_drop >= 0.05 or ratio_value >= 2.0:
        level = "moderate"
    else:
        level = "low"
    return {
        "level": level,
        "diagnostic_only": True,
        "thresholds": {
            "categorical_js_moderate": 0.03,
            "categorical_js_high": 0.10,
            "robust_shift_iqr_moderate": 0.5,
            "robust_shift_iqr_high": 1.0,
            "core_evidence_drop_moderate": 0.05,
            "core_evidence_drop_high": 0.15,
            "accept_change_rate_ratio_moderate": 2.0,
        },
        "observed": {
            "prediction_js_bits": prediction_js,
            "base_action_js_bits": base_action_js,
            "max_abs_robust_shift_iqr": max_robust,
            "max_core_evidence_drop": max_core_drop,
            "accept_change_rate_ratio": ratio,
        },
    }


def audit_drift(
    reference_rows: list[dict[str, Any]],
    frozen_rows: list[dict[str, Any]],
    *,
    reference_evidence: dict[str, dict[str, float]] | None = None,
    frozen_evidence: dict[str, dict[str, float]] | None = None,
    router_manifest: dict[str, Any] | None = None,
    core_evidence_keys: list[str] | None = None,
    top_feature_shifts: int = 20,
) -> dict[str, Any]:
    if not reference_rows or not frozen_rows:
        raise ValueError("reference and frozen rows must be non-empty")
    reference_evidence = reference_evidence or {}
    frozen_evidence = frozen_evidence or {}
    core_evidence_keys = list(core_evidence_keys or DEFAULT_CORE_EVIDENCE)

    reference_accept = [row for row in reference_rows if _base_action(row) == "accept"]
    frozen_accept = [row for row in frozen_rows if _base_action(row) == "accept"]
    actual_reference_router = _actual_router_stats(reference_rows)
    reference_router = actual_reference_router or _manifest_router_stats(router_manifest)
    frozen_router = _actual_router_stats(frozen_rows)

    if reference_router is None:
        reference_router = (len(reference_accept), 0)
    if frozen_router is None:
        frozen_router = (len(frozen_accept), 0)
    ref_legacy, ref_changed = reference_router
    frozen_legacy, frozen_changed = frozen_router
    reference_change_rate = ref_changed / max(1, ref_legacy)
    frozen_change_rate = frozen_changed / max(1, frozen_legacy)
    if reference_change_rate > 0.0:
        change_ratio: float | None = frozen_change_rate / reference_change_rate
    elif frozen_change_rate == 0.0:
        change_ratio = 1.0
    else:
        change_ratio = None

    all_evidence_keys = sorted(
        {key for features in reference_evidence.values() for key in features}
        | {key for features in frozen_evidence.values() for key in features}
    )
    ref_cov = evidence_coverage(reference_evidence, all_evidence_keys)
    frozen_cov = evidence_coverage(frozen_evidence, all_evidence_keys)
    coverage_shifts = [
        {
            "key": key,
            "reference": ref_cov[key],
            "frozen": frozen_cov[key],
            "delta": frozen_cov[key] - ref_cov[key],
            "abs_delta": abs(frozen_cov[key] - ref_cov[key]),
        }
        for key in all_evidence_keys
    ]
    coverage_shifts.sort(key=lambda row: (-row["abs_delta"], row["key"]))
    core = {
        key: {
            "reference": ref_cov.get(key, 0.0),
            "frozen": frozen_cov.get(key, 0.0),
            "delta": frozen_cov.get(key, 0.0) - ref_cov.get(key, 0.0),
        }
        for key in core_evidence_keys
    }

    summary: dict[str, Any] = {
        "format": DRIFT_AUDIT_FORMAT,
        "labels_available": False,
        "reference_rows": len(reference_rows),
        "frozen_rows": len(frozen_rows),
        "categorical_shift": {
            "prediction": distribution_payload(
                (str(row.get("prediction")) for row in reference_rows),
                (str(row.get("prediction")) for row in frozen_rows),
            ),
            "base_action": distribution_payload(
                (_base_action(row) for row in reference_rows),
                (_base_action(row) for row in frozen_rows),
            ),
            "routed_action": distribution_payload(
                _routed_reference_actions(
                    reference_rows,
                    reference_router,
                    actual_router_stats=actual_reference_router,
                ),
                (str(row.get("action")) for row in frozen_rows),
            ),
        },
        "router_intervention": {
            "reference_legacy_accept": ref_legacy,
            "reference_changed": ref_changed,
            "reference_change_fraction_all": ref_changed / len(reference_rows),
            "reference_change_fraction_accept": reference_change_rate,
            "frozen_legacy_accept": frozen_legacy,
            "frozen_changed": frozen_changed,
            "frozen_change_fraction_all": frozen_changed / len(frozen_rows),
            "frozen_change_fraction_accept": frozen_change_rate,
            "accept_change_rate_ratio": change_ratio,
        },
        "numeric_shift_all": {
            key: numeric_shift(reference_rows, frozen_rows, key)
            for key in CORE_NUMERIC
        },
        "numeric_shift_base_accept": {
            key: numeric_shift(reference_accept, frozen_accept, key)
            for key in CORE_NUMERIC
        },
        "evidence_shift": {
            "reference_rows": len(reference_evidence),
            "frozen_rows": len(frozen_evidence),
            "core": core,
            "top_feature_coverage_shifts": coverage_shifts[: max(0, top_feature_shifts)],
        },
        "note": "Unlabeled diagnostic only. Distribution shift does not imply semantic error.",
    }
    summary["severity"] = severity(summary)
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reference_classified", type=Path)
    parser.add_argument("frozen_classified", type=Path)
    parser.add_argument("--reference-base-actions", type=Path)
    parser.add_argument("--reference-evidence", type=Path)
    parser.add_argument("--frozen-evidence", type=Path)
    parser.add_argument("--router-manifest", type=Path)
    parser.add_argument("--core-evidence-key", action="append", default=[])
    parser.add_argument("--top-feature-shifts", type=int, default=20)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    reference_rows = read_jsonl(args.reference_classified)
    if args.reference_base_actions is not None:
        reference_rows = overlay_reference_base_actions(
            reference_rows,
            read_jsonl(args.reference_base_actions),
        )
    frozen_rows = read_jsonl(args.frozen_classified)
    reference_evidence = load_evidence(args.reference_evidence)
    frozen_evidence = load_evidence(args.frozen_evidence)
    manifest = (
        json.loads(args.router_manifest.read_text(encoding="utf-8"))
        if args.router_manifest is not None
        else None
    )
    summary = audit_drift(
        reference_rows,
        frozen_rows,
        reference_evidence=reference_evidence,
        frozen_evidence=frozen_evidence,
        router_manifest=manifest,
        core_evidence_keys=args.core_evidence_key or None,
        top_feature_shifts=args.top_feature_shifts,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    prediction_js = summary["categorical_shift"]["prediction"]["js_divergence_bits"]
    action_js = summary["categorical_shift"]["base_action"]["js_divergence_bits"]
    intervention = summary["router_intervention"]
    print("format:", summary["format"])
    print("reference rows:", summary["reference_rows"], "frozen rows:", summary["frozen_rows"])
    print("prediction JS bits:", round(float(prediction_js), 6))
    print("base-action JS bits:", round(float(action_js), 6))
    print(
        "router change among accept: reference=",
        round(float(intervention["reference_change_fraction_accept"]), 6),
        "frozen=",
        round(float(intervention["frozen_change_fraction_accept"]), 6),
        "ratio=",
        intervention["accept_change_rate_ratio"],
    )
    print("core evidence:", summary["evidence_shift"]["core"])
    print("drift severity:", summary["severity"]["level"], "(diagnostic only)")
    print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
