from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.runtime_intervention import InterventionError, compare_files

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "docs/evidence/runtime-differential-v1/nevergone-synthetic/differential.json"
MANIFEST_SCHEMA = json.loads((ROOT / "schemas/runtime-intervention-manifest-v1.schema.json").read_text(encoding="utf-8"))
REPORT_SCHEMA = json.loads((ROOT / "schemas/runtime-intervention-evidence-v1.schema.json").read_text(encoding="utf-8"))


def _write_collection(
    tmp_path: Path, *, mixed: bool = False, incomplete: bool = False,
    duplicate_source: bool = False, one_off: bool = False,
) -> Path:
    template = json.loads(FIXTURE.read_text(encoding="utf-8"))
    intervention = deepcopy(template["intervention"])
    comparisons = []
    for index in range(3):
        report = deepcopy(template)
        report["comparison_id"] = f"synthetic-pair-{index + 1}"
        report["baseline_capture_id"] = f"baseline-capture-{index + 1}"
        report["treatment_capture_id"] = f"treatment-capture-{index + 1}"
        report["baseline_report_sha256"] = hashlib.sha256(f"baseline-{index}".encode()).hexdigest()
        report["treatment_report_sha256"] = hashlib.sha256(f"treatment-{index}".encode()).hexdigest()
        report["sampling"] = {
            "baseline": {"status": "complete", "gaps": []},
            "treatment": {"status": "complete", "gaps": []},
        }
        if mixed and index == 2:
            candidate = report["ranked_candidates"][0]
            candidate.update({"baseline_count": 1, "treatment_count": 0, "delta": -1, "change": "removed"})
        if one_off and index > 0:
            report["ranked_candidates"] = []
            report["summary"]["changed_signature_count"] = 0
        if incomplete and index == 2:
            report["sampling"]["treatment"]["status"] = "unknown"
        if duplicate_source and index == 2:
            report["baseline_report_sha256"] = comparisons[0]["_baseline_sha256"]
        report_path = tmp_path / f"pair-{index + 1}.json"
        raw = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
        report_path.write_bytes(raw)
        comparison = {
            "comparison_id": report["comparison_id"],
            "report_path": report_path.name,
            "report_sha256": hashlib.sha256(raw).hexdigest(),
        }
        if duplicate_source and index == 0:
            comparison["_baseline_sha256"] = report["baseline_report_sha256"]
        comparisons.append(comparison)
    for comparison in comparisons:
        comparison.pop("_baseline_sha256", None)
    manifest = {
        "format": "REVENGINSTR.RuntimeInterventionManifest/1",
        "collection_id": "synthetic-repeatability-check",
        "intervention": intervention,
        "observation_window_sha256": hashlib.sha256(b"same synthetic observation window").hexdigest(),
        "comparisons": comparisons,
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def test_three_complete_same_direction_pairs_support_candidate(tmp_path: Path) -> None:
    manifest_path = _write_collection(tmp_path)
    report = compare_files(manifest_path, tmp_path / "evidence.json")
    Draft202012Validator.check_schema(MANIFEST_SCHEMA)
    Draft202012Validator.check_schema(REPORT_SCHEMA)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    Draft202012Validator(MANIFEST_SCHEMA).validate(manifest)
    Draft202012Validator(REPORT_SCHEMA).validate(report)
    candidate = report["ranked_candidates"][0]
    assert candidate["evidence_class"] == "intervention_support"
    assert candidate["support_repetition_count"] == 3
    assert candidate["pairwise_deltas"] == [
        {"comparison_id": f"synthetic-pair-{index}", "delta": 1} for index in range(1, 4)
    ]


@pytest.mark.parametrize("options", [{"mixed": True}, {"incomplete": True}])
def test_mixed_or_incomplete_repeats_remain_correlation(tmp_path: Path, options: dict[str, bool]) -> None:
    manifest_path = _write_collection(tmp_path, **options)
    report = compare_files(manifest_path, tmp_path / "evidence.json")
    assert report["ranked_candidates"][0]["evidence_class"] == "correlation"


def test_repeated_comparisons_must_pin_distinct_source_reports(tmp_path: Path) -> None:
    manifest_path = _write_collection(tmp_path, duplicate_source=True)
    with pytest.raises(InterventionError, match="distinct source correlation reports"):
        compare_files(manifest_path, tmp_path / "evidence.json")


def test_signature_missing_from_a_pair_counts_as_zero_change(tmp_path: Path) -> None:
    manifest_path = _write_collection(tmp_path, one_off=True)
    report = compare_files(manifest_path, tmp_path / "evidence.json")
    candidate = report["ranked_candidates"][0]
    assert candidate["unchanged_pair_count"] == 2
    assert candidate["median_delta"] == 0
    assert len(candidate["pairwise_deltas"]) == 1
    assert candidate["evidence_class"] == "correlation"
