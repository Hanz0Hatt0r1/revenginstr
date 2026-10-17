"""Compare standardized benchmark summaries and report numeric metric deltas."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import sys
from pathlib import Path
from typing import Any

FORMAT = "REVENGINSTR.BenchmarkDelta/1"
SUMMARY_FORMAT = "REVENGINSTR.BenchmarkSummary/1"


class DeltaError(ValueError):
    """Benchmark summaries cannot be compared under the shared contract."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _pointer_part(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def numeric_metrics(summary: dict[str, Any]) -> dict[str, float | None]:
    metrics: dict[str, float | None] = {}

    def add(name: str, value: Any) -> None:
        if name in metrics:
            raise DeltaError(f"duplicate metric name: {name}")
        if value is None:
            metrics[name] = None
        elif isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
            raise DeltaError(f"metric is not a finite number: {name}")
        else:
            metrics[name] = float(value)

    for item in summary.get("metrics", []):
        add(f"/metrics/{_pointer_part(str(item['name']))}", item.get("value"))

    for projection in summary.get("projections", []):
        prefix = f"/projections/{_pointer_part(str(projection['id']))}"
        if "row_count" in projection:
            add(f"{prefix}/row_count", projection["row_count"])
        for label, count in projection.get("class_distribution", {}).items():
            add(f"{prefix}/class_distribution/{_pointer_part(label)}", count)
        classification = projection.get("classification", {})
        for name in ("macro_f1", "balanced_accuracy"):
            if name in classification:
                add(f"{prefix}/classification/{name}", classification[name])
        for label, values in classification.get("per_class", {}).items():
            for name in ("precision", "recall", "f1", "support"):
                if name in values:
                    add(f"{prefix}/classification/per_class/{_pointer_part(label)}/{name}", values[name])
        classes = classification.get("classes", [])
        confusion = classification.get("confusion_matrix", [])
        for actual_index, row in enumerate(confusion):
            if actual_index >= len(classes):
                break
            for predicted_index, count in enumerate(row):
                if predicted_index >= len(classes):
                    break
                actual = _pointer_part(classes[actual_index])
                predicted = _pointer_part(classes[predicted_index])
                add(f"{prefix}/classification/confusion_matrix/{actual}/{predicted}", count)
        coverage = projection.get("coverage", {})
        for name in ("accepted_rows", "abstained_rows", "accepted_fraction", "abstained_fraction", "accepted_accuracy"):
            if name in coverage:
                add(f"{prefix}/coverage/{name}", coverage[name])
        for action, count in coverage.get("action_counts", {}).items():
            add(f"{prefix}/coverage/action_counts/{_pointer_part(action)}", count)
        calibration = projection.get("calibration", {})
        for name in ("sample_count", "excluded_count", "expected_calibration_error", "brier_score"):
            if name in calibration:
                add(f"{prefix}/calibration/{name}", calibration[name])
        for bin_index, bin_metrics in enumerate(calibration.get("bins", [])):
            for name, value in bin_metrics.items():
                if name in {"lower_bound", "upper_bound", "count", "mean_confidence", "observed_accuracy"}:
                    add(f"{prefix}/calibration/bins/{bin_index}/{name}", value)
        receiver = projection.get("receiver", {})
        for name in ("resolved_rows", "coverage"):
            if name in receiver:
                add(f"{prefix}/receiver/{name}", receiver[name])
        for status, count in receiver.get("status_counts", {}).items():
            add(f"{prefix}/receiver/status_counts/{_pointer_part(status)}", count)
        assessment = projection.get("receiver_assessment", {})
        for name in ("rows_with_unknown_candidates", "unknown_candidate_total", "compatibility_group_rows"):
            if name in assessment:
                add(f"{prefix}/receiver_assessment/{name}", assessment[name])
        for group, counts in assessment.get("status_counts", {}).items():
            add(f"{prefix}/receiver_assessment/status_counts/{_pointer_part(group)}", counts)
        for count, rows in assessment.get("candidate_count_counts", {}).items():
            add(f"{prefix}/receiver_assessment/candidate_count_counts/{_pointer_part(count)}", rows)
        exact = projection.get("exact_evidence")
        if isinstance(exact, dict):
            for name in ("actual_rows", "expected_rows", "compared_rows", "mismatched_rows", "missing_rows", "unexpected_rows", "mismatch_rows"):
                add(f"{prefix}/exact_evidence/{name}", exact[name])
            add(f"{prefix}/exact_evidence/maximum_mismatches", exact["maximum_mismatches"])
        for category, reasons in projection.get("reason_counts", {}).items():
            for reason, count in reasons.items():
                add(f"{prefix}/reason_counts/{_pointer_part(category)}/{_pointer_part(reason)}", count)
        validation = projection.get("validation", {})
        for name in ("reference_rows", "frozen_rows"):
            if name in validation:
                add(f"{prefix}/validation/{name}", validation[name])
        for name, value in validation.get("selection", {}).items():
            add(f"{prefix}/validation/selection/{_pointer_part(name)}", value)
        for name, value in validation.get("router_intervention", {}).items():
            add(f"{prefix}/validation/router_intervention/{_pointer_part(name)}", value)
    return metrics


def compare_summaries(baseline: dict[str, Any], candidate: dict[str, Any], *,
                      baseline_sha256: str, candidate_sha256: str) -> dict[str, Any]:
    if baseline.get("format") != SUMMARY_FORMAT or candidate.get("format") != SUMMARY_FORMAT:
        raise DeltaError(f"both files must use {SUMMARY_FORMAT}")
    if baseline.get("mode") != candidate.get("mode"):
        raise DeltaError("benchmark modes must match")
    baseline_identity = baseline.get("benchmark", {})
    candidate_identity = candidate.get("benchmark", {})
    identity_fields = ("dataset_id", "split_id", "family_set_id")
    if any(baseline_identity.get(field) != candidate_identity.get(field) for field in identity_fields):
        raise DeltaError("benchmark dataset, split, and family-set identities must match")

    baseline_metrics = numeric_metrics(baseline)
    candidate_metrics = numeric_metrics(candidate)
    deltas = []
    for name in sorted(set(baseline_metrics) | set(candidate_metrics)):
        before = baseline_metrics.get(name)
        after = candidate_metrics.get(name)
        deltas.append({
            "name": name,
            "baseline": before,
            "candidate": after,
            "delta": after - before if before is not None and after is not None else None,
        })
    return {
        "format": FORMAT,
        "benchmark": {field: baseline_identity.get(field) for field in identity_fields},
        "mode": baseline.get("mode"),
        "baseline_summary_sha256": baseline_sha256,
        "candidate_summary_sha256": candidate_sha256,
        "baseline_status": baseline.get("status"),
        "candidate_status": candidate.get("status"),
        "metrics": deltas,
    }


def compare_files(baseline_path: Path, candidate_path: Path, output_path: Path) -> dict[str, Any]:
    baseline_path = baseline_path.resolve()
    candidate_path = candidate_path.resolve()
    output_path = output_path.resolve()
    if output_path in {baseline_path, candidate_path}:
        raise DeltaError("delta output cannot overwrite either input summary")
    try:
        baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
        candidate = json.loads(candidate_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise DeltaError(f"invalid benchmark summary JSON: {exc}") from exc
    if not isinstance(baseline, dict) or not isinstance(candidate, dict):
        raise DeltaError("benchmark summary roots must be JSON objects")
    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:
        raise DeltaError("benchmark summary validation requires jsonschema; install revenginstr[benchmark]") from exc
    summary_schema_path = Path(__file__).resolve().parents[2] / "schemas" / "benchmark-summary-v1.schema.json"
    if not summary_schema_path.is_file():
        summary_schema_path = Path(sys.prefix) / "share" / "revenginstr" / "schemas" / summary_schema_path.name
    summary_schema = json.loads(summary_schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(summary_schema)
    for label, summary in (("baseline", baseline), ("candidate", candidate)):
        errors = list(validator.iter_errors(summary))
        if errors:
            error = errors[0]
            location = "/".join(str(part) for part in error.absolute_path) or "<root>"
            raise DeltaError(f"{label} summary {location}: {error.message}")
    delta = compare_summaries(
        baseline, candidate,
        baseline_sha256=_sha256(baseline_path), candidate_sha256=_sha256(candidate_path),
    )
    _write_delta(output_path, delta)
    return delta


def _write_delta(path: Path, delta: dict[str, Any]) -> None:
    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:
        raise DeltaError("benchmark delta schema validation requires jsonschema; install revenginstr[benchmark]") from exc
    schema_path = Path(__file__).resolve().parents[2] / "schemas" / "benchmark-delta-v1.schema.json"
    if not schema_path.is_file():
        schema_path = Path(sys.prefix) / "share" / "revenginstr" / "schemas" / schema_path.name
    if path.resolve() == schema_path.resolve():
        raise DeltaError("delta output cannot overwrite its schema")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    errors = list(Draft202012Validator(schema).iter_errors(delta))
    if errors:
        raise DeltaError(f"generated benchmark delta is invalid: {errors[0].message}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(delta, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("candidate", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        delta = compare_files(args.baseline, args.candidate, args.output)
    except (DeltaError, OSError) as exc:
        parser.exit(2, f"benchmark delta failed: {exc}\n")
    print(f"compared metrics: {len(delta['metrics'])}")
    print(f"delta: {args.output.resolve()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
