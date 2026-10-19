from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.runtime_probe_evaluation import ProbeEvaluationError, evaluate_probe_set

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "docs/evidence/runtime-probe-evaluation-v1/nevergone-synthetic"
MANIFEST_SCHEMA = json.loads((ROOT / "schemas/runtime-probe-evaluation-manifest-v1.schema.json").read_text())
OUTCOME_SCHEMA = json.loads((ROOT / "schemas/runtime-probe-outcome-v1.schema.json").read_text())
REPORT_SCHEMA = json.loads((ROOT / "schemas/runtime-probe-evaluation-v1.schema.json").read_text())


def _inputs() -> tuple[dict, bytes, dict, bytes, list[dict], bytes]:
    manifest_raw = (FIXTURE / "evaluation-manifest.json").read_bytes()
    manifest = json.loads(manifest_raw)
    plan_raw = (FIXTURE / "request-plan.json").read_bytes()
    plan = json.loads(plan_raw)
    outcomes_raw = (FIXTURE / "outcomes.jsonl").read_bytes()
    outcomes = [json.loads(line) for line in outcomes_raw.splitlines() if line.strip()]
    return manifest, manifest_raw, plan, plan_raw, outcomes, outcomes_raw


def test_pinned_synthetic_set_reports_all_m95_metrics() -> None:
    manifest, manifest_raw, plan, plan_raw, outcomes, outcomes_raw = _inputs()
    report = evaluate_probe_set(manifest, manifest_raw, plan, plan_raw, outcomes, outcomes_raw)
    Draft202012Validator.check_schema(MANIFEST_SCHEMA)
    Draft202012Validator.check_schema(OUTCOME_SCHEMA)
    Draft202012Validator.check_schema(REPORT_SCHEMA)
    Draft202012Validator(MANIFEST_SCHEMA).validate(manifest)
    for outcome in outcomes:
        Draft202012Validator(OUTCOME_SCHEMA).validate(outcome)
    Draft202012Validator(REPORT_SCHEMA).validate(report)
    metrics = report["metrics"]
    assert metrics["completion_rate_ppm"] == 750_000
    assert metrics["requested_cost_units_total"] == 10
    assert metrics["actual_steps_total"] == 310
    assert metrics["elapsed_ms_total"] == 10_200
    assert metrics["decisive_rate_of_completed_ppm"] == 666_666
    assert metrics["uncertainty_reduction_total_milli"] == 750
    assert metrics["unlocked_decision_ids"] == ["next-a", "next-b"]
    assert metrics["static_disagreement_rate_ppm"] == 500_000


def test_plan_hash_mismatch_fails_closed() -> None:
    manifest, manifest_raw, plan, plan_raw, outcomes, outcomes_raw = _inputs()
    manifest["plan_sha256"] = "0" * 64
    with pytest.raises(ProbeEvaluationError, match="plan hash mismatch"):
        evaluate_probe_set(manifest, manifest_raw, plan, plan_raw, outcomes, outcomes_raw)


def test_resource_overrun_is_rejected() -> None:
    manifest, manifest_raw, plan, plan_raw, outcomes, outcomes_raw = _inputs()
    outcomes[0]["actual_steps"] = 101
    with pytest.raises(ProbeEvaluationError, match="exceeded declared probe bounds"):
        evaluate_probe_set(manifest, manifest_raw, plan, plan_raw, outcomes, outcomes_raw)


def test_all_incomplete_probes_have_null_decisive_rate() -> None:
    manifest, manifest_raw, plan, plan_raw, outcomes, outcomes_raw = _inputs()
    for row in outcomes:
        row.update(status="incomplete", decision=None, uncertainty_after_milli=None, unlocked_decision_ids=[])
    outcomes_raw = b"".join((json.dumps(row, sort_keys=True) + "\n").encode() for row in outcomes)
    report = evaluate_probe_set(manifest, manifest_raw, plan, plan_raw, outcomes, outcomes_raw)
    assert report["metrics"]["completed_count"] == 0
    assert report["metrics"]["decisive_rate_of_completed_ppm"] is None
    assert report["metrics"]["static_disagreement_rate_ppm"] is None
