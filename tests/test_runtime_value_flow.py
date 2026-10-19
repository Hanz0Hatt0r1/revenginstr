from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.runtime_value_flow import RuntimeValueFlowError, replay_value_flow

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "docs/evidence/runtime-value-flow-v1/nevergone-synthetic"
MANIFEST_SCHEMA = json.loads((ROOT / "schemas/runtime-value-flow-manifest-v1.schema.json").read_text())
OBSERVATION_SCHEMA = json.loads((ROOT / "schemas/runtime-value-observation-v1.schema.json").read_text())
REPORT_SCHEMA = json.loads((ROOT / "schemas/runtime-value-flow-replay-v1.schema.json").read_text())


def _inputs() -> tuple[dict, dict, bytes, list[dict], bytes]:
    manifest = json.loads((FIXTURE / "manifest.json").read_text())
    correlation_raw = (FIXTURE / "correlation-report.json").read_bytes()
    correlation = json.loads(correlation_raw)
    observations_raw = (FIXTURE / "value-observations.jsonl").read_bytes()
    observations = [json.loads(line) for line in observations_raw.splitlines() if line.strip()]
    return manifest, correlation, correlation_raw, observations, observations_raw


def _replay(
    manifest: dict, correlation: dict, observations: list[dict],
) -> dict:
    correlation_raw = (json.dumps(correlation, sort_keys=True) + "\n").encode()
    observations_raw = b"".join((json.dumps(row, sort_keys=True) + "\n").encode() for row in observations)
    manifest = deepcopy(manifest)
    manifest["correlation_report_sha256"] = hashlib.sha256(correlation_raw).hexdigest()
    manifest["observations_sha256"] = hashlib.sha256(observations_raw).hexdigest()
    return replay_value_flow(manifest, correlation, correlation_raw, observations, observations_raw)


def test_pinned_synthetic_field_pair_is_a_scoped_witness() -> None:
    manifest, correlation, correlation_raw, observations, observations_raw = _inputs()
    report = replay_value_flow(manifest, correlation, correlation_raw, observations, observations_raw)
    Draft202012Validator.check_schema(MANIFEST_SCHEMA)
    Draft202012Validator.check_schema(OBSERVATION_SCHEMA)
    Draft202012Validator.check_schema(REPORT_SCHEMA)
    Draft202012Validator(MANIFEST_SCHEMA).validate(manifest)
    for row in observations:
        Draft202012Validator(OBSERVATION_SCHEMA).validate(row)
    Draft202012Validator(REPORT_SCHEMA).validate(report)
    assert report["candidates"][0]["status"] == "witnessed"
    assert report["claim_scope"] == "selected_observation_pairs_only"
    assert "hmac-sha256:" not in json.dumps(report)


def test_different_field_value_is_only_a_pair_scoped_mismatch() -> None:
    manifest, correlation, _, observations, _ = _inputs()
    observations[1]["tokens"]["value"] = "hmac-sha256:" + "d" * 64
    report = _replay(manifest, correlation, observations)
    result = report["candidates"][0]
    assert result["status"] == "observed_mismatch"
    assert result["different_token_slots"] == ["value"]
    assert report["summary"]["observed_mismatch"] == 1


@pytest.mark.parametrize("relation,source_kind,sink_kind", [
    ("receiver_identity", "receiver", "receiver"),
    ("state_transition", "state_before", "state_after"),
    ("factory_return_use", "factory_return", "factory_use"),
    ("allocation_release", "allocation", "release"),
])
def test_supported_relation_pairs_replay(relation: str, source_kind: str, sink_kind: str) -> None:
    manifest, correlation, _, observations, _ = _inputs()
    tokens = {"subject": "hmac-sha256:" + "a" * 64}
    source_tokens, sink_tokens = dict(tokens), dict(tokens)
    if relation == "state_transition":
        source_tokens["value"] = "hmac-sha256:" + "b" * 64
        sink_tokens["value"] = "hmac-sha256:" + "c" * 64
    for row, event_kind, event_tokens in zip(observations, (source_kind, sink_kind), (source_tokens, sink_tokens)):
        row["event_kind"] = event_kind
        row["tokens"] = event_tokens
    manifest["candidates"][0]["relation_kind"] = relation
    report = _replay(manifest, correlation, observations)
    assert report["candidates"][0]["status"] == "witnessed"


def test_sampling_gap_makes_selected_pair_inconclusive() -> None:
    manifest, correlation, _, observations, _ = _inputs()
    correlation["sampling"] = {"status": "sampled", "gaps": [{
        "first_sequence": 12, "last_sequence": 12, "reason": "synthetic omitted event",
    }]}
    correlation["events"][1]["sequence"] = 13
    observations[1]["correlation_sequence"] = 13
    manifest["candidates"][0]["sink_sequence"] = 13
    report = _replay(manifest, correlation, observations)
    result = report["candidates"][0]
    assert result["status"] == "inconclusive"
    assert result["reason"] == "declared_sampling_gap_intersects_pair"


def test_unexpected_static_node_and_wrong_address_do_not_witness() -> None:
    manifest, correlation, _, observations, _ = _inputs()
    manifest["candidates"][0]["expected_source_node_id"] = "other-node"
    report = _replay(manifest, correlation, observations)
    assert report["candidates"][0]["status"] == "inconclusive"
    assert report["candidates"][0]["reason"] == "static_location_not_uniquely_matched_to_expected_node"

    manifest, correlation, _, observations, _ = _inputs()
    observations[0]["runtime_address"] = "0x2030"
    report = _replay(manifest, correlation, observations)
    assert report["candidates"][0]["status"] == "inconclusive"
    assert report["candidates"][0]["reason"] == "value_observation_address_does_not_match_correlation"


def test_hash_mismatch_fails_closed() -> None:
    manifest, correlation, correlation_raw, observations, observations_raw = _inputs()
    manifest["observations_sha256"] = "0" * 64
    with pytest.raises(RuntimeValueFlowError, match="value observations hash mismatch"):
        replay_value_flow(manifest, correlation, correlation_raw, observations, observations_raw)
