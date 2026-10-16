from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.benchmark_delta import DeltaError, compare_files, compare_summaries

ROOT = Path(__file__).resolve().parents[1]


def _summary(*, macro_f1: float, precision: float) -> dict:
    return {
        "format": "REVENGINSTR.BenchmarkSummary/1",
        "benchmark": {
            "id": "synthetic-v1", "dataset_id": "dataset-a", "split_id": "holdout",
            "family_set_id": "families-a",
        },
        "mode": "full",
        "status": "passed",
        "manifest_sha256": "a" * 64,
        "tool_version": "0.5.2",
        "toolchain": {"revenginstr_version": "0.5.2"},
        "schema_versions": {},
        "configuration_sha256": "b" * 64,
        "artifacts": {},
        "stages": [],
        "metrics": [{"name": "corpus_rows", "artifact": "audit", "json_pointer": "/corpus/rows", "value": 12, "passed": True}],
        "projections": [{
            "id": "classifier", "kind": "classifier", "artifact": "predictions", "row_count": 12,
            "class_distribution": {"alpha": 12},
            "classification": {
                "classes": ["alpha"], "confusion_matrix": [[12]], "macro_f1": macro_f1,
                "balanced_accuracy": macro_f1,
                "per_class": {"alpha": {"precision": precision, "recall": macro_f1, "f1": macro_f1, "support": 12}},
            },
            "coverage": {"accepted_rows": 8, "abstained_rows": 4, "accepted_fraction": 2 / 3,
                         "abstained_fraction": 1 / 3, "accepted_accuracy": precision,
                         "action_counts": {"accept": 8, "review": 4}},
            "exact_evidence": None,
        }],
        "gate_failures": [],
    }


def test_delta_reports_numeric_metric_and_projection_changes() -> None:
    baseline = _summary(macro_f1=0.8, precision=0.75)
    candidate = _summary(macro_f1=0.9, precision=0.875)

    delta = compare_summaries(baseline, candidate, baseline_sha256="a" * 64, candidate_sha256="b" * 64)
    values = {item["name"]: item for item in delta["metrics"]}

    assert values["/projections/classifier/classification/macro_f1"]["delta"] == pytest.approx(0.1)
    assert values["/projections/classifier/classification/per_class/alpha/precision"]["delta"] == pytest.approx(0.125)
    assert values["/metrics/corpus_rows"]["delta"] == 0.0


def test_delta_requires_matching_dataset_split_and_family_identity() -> None:
    baseline = _summary(macro_f1=0.8, precision=0.75)
    candidate = _summary(macro_f1=0.9, precision=0.875)
    candidate["benchmark"]["split_id"] = "train"

    with pytest.raises(DeltaError, match="identities must match"):
        compare_summaries(baseline, candidate, baseline_sha256="a" * 64, candidate_sha256="b" * 64)

    candidate["benchmark"]["split_id"] = "holdout"
    candidate["mode"] = "smoke"
    with pytest.raises(DeltaError, match="modes must match"):
        compare_summaries(baseline, candidate, baseline_sha256="a" * 64, candidate_sha256="b" * 64)


def test_delta_cli_output_is_schema_validated(tmp_path: Path) -> None:
    baseline_path = tmp_path / "baseline.json"
    candidate_path = tmp_path / "candidate.json"
    output_path = tmp_path / "delta.json"
    baseline_path.write_text(json.dumps(_summary(macro_f1=0.8, precision=0.75)), encoding="utf-8")
    candidate_path.write_text(json.dumps(_summary(macro_f1=0.9, precision=0.875)), encoding="utf-8")

    delta = compare_files(baseline_path, candidate_path, output_path)
    schema = json.loads((ROOT / "schemas" / "benchmark-delta-v1.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(delta)
    assert json.loads(output_path.read_text(encoding="utf-8")) == delta
