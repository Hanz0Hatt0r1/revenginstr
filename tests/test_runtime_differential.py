from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.runtime_differential import DifferentialError, _validate_report, compare_files

ROOT = Path(__file__).resolve().parents[1]
REPLAY_DIR = ROOT / "docs/evidence/runtime-differential-v1/nevergone-synthetic"
SCHEMAS = {
    name: json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
    for name in (
        "runtime-differential-manifest-v1.schema.json",
        "runtime-differential-v1.schema.json",
    )
}


def test_pinned_synthetic_runtime_differential_replay(tmp_path: Path) -> None:
    replay = json.loads((REPLAY_DIR / "replay-manifest.json").read_text(encoding="utf-8"))
    assert replay["format"] == "REVENGINSTR.RuntimeDifferentialReplay/1"
    for artifact in replay["artifacts"]:
        raw = (REPLAY_DIR / artifact["path"]).resolve().read_bytes()
        assert len(raw) == artifact["bytes"]
        assert hashlib.sha256(raw).hexdigest() == artifact["sha256"]

    baseline_path = (REPLAY_DIR / "../../runtime-static-correlation-v1/nevergone-synthetic/correlation.json").resolve()
    treatment_path = REPLAY_DIR / "treatment-correlation.json"
    manifest_path = REPLAY_DIR / "intervention.json"
    output_path = tmp_path / "differential.json"
    report = compare_files(baseline_path, treatment_path, manifest_path, output_path)

    for schema in SCHEMAS.values():
        Draft202012Validator.check_schema(schema)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    Draft202012Validator(SCHEMAS["runtime-differential-manifest-v1.schema.json"]).validate(manifest)
    Draft202012Validator(SCHEMAS["runtime-differential-v1.schema.json"]).validate(report)
    assert report == json.loads((REPLAY_DIR / "differential.json").read_text(encoding="utf-8"))
    assert report["summary"]["changed_signature_count"] == 1
    candidate = report["ranked_candidates"][0]
    assert candidate["normalized_address"] == "0x32a4ec"
    assert candidate["change"] == "added"
    assert candidate["evidence_class"] == "correlation"
    assert candidate["function_entries"] == ["0032a4ec"]
    assert json.loads(output_path.read_text(encoding="utf-8")) == report


def test_runtime_differential_fails_closed_on_unpinned_reports(tmp_path: Path) -> None:
    baseline_path = (REPLAY_DIR / "../../runtime-static-correlation-v1/nevergone-synthetic/correlation.json").resolve()
    treatment_path = REPLAY_DIR / "treatment-correlation.json"
    manifest = json.loads((REPLAY_DIR / "intervention.json").read_text(encoding="utf-8"))
    manifest["baseline_report_sha256"] = "0" * 64
    manifest_path = tmp_path / "intervention.json"
    manifest_path.write_text(json.dumps(manifest) + "\n", encoding="utf-8")
    with pytest.raises(DifferentialError, match="does not pin the baseline report"):
        compare_files(baseline_path, treatment_path, manifest_path, tmp_path / "rejected.json")


def test_report_validation_handles_negative_module_delta() -> None:
    path = (REPLAY_DIR / "../../runtime-static-correlation-v1/nevergone-synthetic/correlation.json").resolve()
    report = deepcopy(json.loads(path.read_text(encoding="utf-8")))
    report["address_mapping"].update({
        "runtime_module_base": "0x70000000",
        "static_image_base": "0x80000000",
        "module_delta": "-0x10000000",
    })
    state_counts = {"matched": 0, "ambiguous": 0, "unmatched": 0, "mapping_underflow": 0, "mapping_overflow": 0}
    for event in report["events"]:
        normalized = int(event["runtime_address"], 16) + 0x10000000
        event["normalized_address"] = f"0x{normalized:x}"
        if event["match_state"] == "mapping_underflow":
            event["match_state"] = "unmatched"
        state_counts[event["match_state"]] += 1
    report["summary"] = {
        "event_count": len(report["events"]),
        "matched_count": state_counts["matched"],
        "ambiguous_count": state_counts["ambiguous"],
        "unmatched_count": state_counts["unmatched"],
        "mapping_underflow_count": state_counts["mapping_underflow"],
        "mapping_overflow_count": state_counts["mapping_overflow"],
    }
    _validate_report(report, "negative-delta report")


def test_report_validation_rejects_normalized_addresses_in_wrong_space() -> None:
    path = REPLAY_DIR / "treatment-correlation.json"
    report = deepcopy(json.loads(path.read_text(encoding="utf-8")))
    report["events"][0]["normalized_address"] = "0x0"
    with pytest.raises(DifferentialError, match="normalized_address conflicts with mapping"):
        _validate_report(report, "mutated report")
