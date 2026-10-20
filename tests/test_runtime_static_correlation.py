from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.benchmark import run_benchmark
from revenginstr.runtime_static_correlation import (
    CAPTURE_FORMAT,
    OBSERVATION_FORMAT,
    STATIC_IDENTITY_FORMAT,
    correlate_runtime_addresses,
    main,
)
from revenginstr.semantic_program_graph import _read_jsonl

ROOT = Path(__file__).resolve().parents[1]
GRAPH_PATH = ROOT / "docs/evidence/semantic-program-graph-v3/nevergone-ccjoystick/semantic-program-graph.jsonl"
PROGRAM_MANIFEST_PATH = ROOT / "docs/evidence/semantic-program-graph-v3/nevergone-ccjoystick/manifest.json"
RUNTIME_GRAPH_PATH = ROOT / "docs/evidence/semantic-program-graph-v3/nevergone-runtime-correlation-20261020/semantic-program-graph.jsonl"
REPLAY_DIR = ROOT / "docs/evidence/runtime-static-correlation-v1/nevergone-synthetic"
DEVICE_ARTIFACT_IDENTITY_PATH = (
    ROOT / "docs/evidence/runtime-static-correlation-v1/nevergone-device-artifact-20261019/artifact-identity.json"
)
DEVICE_RUNTIME_REPLAY_DIR = ROOT / "docs/evidence/runtime-static-correlation-v1/nevergone-device-runtime-20261019"
DEVICE_RUNTIME_STATIC_IDENTITY_PATH = DEVICE_RUNTIME_REPLAY_DIR / "static-identity.json"
SCHEMAS = {
    name: json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
    for name in (
        "runtime-static-identity-v1.schema.json",
        "runtime-capture-manifest-v1.schema.json",
        "runtime-address-observation-v1.schema.json",
        "runtime-static-correlation-v1.schema.json",
    )
}


def test_installed_nevergone_library_matches_pinned_graph_binary() -> None:
    evidence = json.loads(DEVICE_ARTIFACT_IDENTITY_PATH.read_text(encoding="utf-8"))
    graphs, _ = _read_jsonl(GRAPH_PATH)
    program_manifest = json.loads(PROGRAM_MANIFEST_PATH.read_text(encoding="utf-8"))
    address_domain = evidence["address_domain"]
    static_image_base = int(address_domain["static_image_base"], 16)
    graph_function_entries = {
        node["entry"] for node in graphs[0]["nodes"] if node.get("kind") == "function"
    }
    graph_callsites = {
        node["operation_address"]: node.get("target_entries", [])
        for node in graphs[0]["nodes"]
        if node.get("kind") == "operation" and node.get("opcode") == "CALL"
    }

    assert evidence["format"] == "REVENGINSTR.InstalledAndroidNativeArtifactIdentity/1"
    assert evidence["package"]["name"] == "com.hippiegame.nevergone"
    assert evidence["native_library"]["sha256"] == program_manifest["program_sha256"]
    assert evidence["static_graph"]["program_sha256"] == program_manifest["program_sha256"]
    assert evidence["static_graph"]["program_id"] == graphs[0]["program_id"]
    assert address_domain["static_image_base"] == "0x10000"
    for entry in address_domain["symbol_entries"]:
        symbol_value = int(entry["elf_symbol_value"], 16)
        elf_entry = int(entry["elf_code_entry"], 16)
        graph_entry = int(entry["graph_entry"], 16)
        assert elf_entry == symbol_value & ~1
        assert graph_entry - elf_entry == static_image_base
        assert f"{graph_entry:08x}" in graph_function_entries
    for call in address_domain["direct_calls"]:
        elf_callsite = int(call["elf_callsite"], 16)
        elf_target = int(call["elf_target"], 16)
        graph_callsite = int(call["graph_callsite"], 16)
        graph_target = int(call["graph_target"], 16)
        assert graph_callsite - elf_callsite == static_image_base
        assert graph_target - elf_target == static_image_base
        assert f"{graph_target:08x}" in graph_callsites[f"{graph_callsite:08x}"]


def _inputs():
    graphs, graph_sha = _read_jsonl(GRAPH_PATH)
    program_manifest = json.loads(PROGRAM_MANIFEST_PATH.read_text(encoding="utf-8"))
    identity = {
        "format": STATIC_IDENTITY_FORMAT,
        "program_id": graphs[0]["program_id"],
        "program_sha256": program_manifest["program_sha256"],
        "semantic_graph_sha256": graph_sha,
        "static_image_base": "0x10000",
    }
    identity_bytes = (json.dumps(identity, sort_keys=True) + "\n").encode()
    capture = {
        "format": CAPTURE_FORMAT,
        "capture_id": "synthetic-nevergone-module-base-replay",
        "program_id": identity["program_id"],
        "program_sha256": identity["program_sha256"],
        "static_identity_sha256": hashlib.sha256(identity_bytes).hexdigest(),
        "runtime_module_base": "0x70000000",
        "sampling_status": "sampled",
        "sampling_gaps": [{"first_sequence": 5, "last_sequence": 5, "reason": "synthetic dropped event"}],
    }
    observations = [
        {"format": OBSERVATION_FORMAT, "capture_id": capture["capture_id"], "sequence": 0,
         "event_kind": "instruction", "runtime_address": "0x7031de44"},
        {"format": OBSERVATION_FORMAT, "capture_id": capture["capture_id"], "sequence": 1,
         "event_kind": "function_entry", "runtime_address": "0x7031ddee"},
        {"format": OBSERVATION_FORMAT, "capture_id": capture["capture_id"], "sequence": 2,
         "event_kind": "call_target", "runtime_address": "0x70539756"},
        {"format": OBSERVATION_FORMAT, "capture_id": capture["capture_id"], "sequence": 3,
         "event_kind": "instruction", "runtime_address": "0x70100000"},
        {"format": OBSERVATION_FORMAT, "capture_id": capture["capture_id"], "sequence": 4,
         "event_kind": "instruction", "runtime_address": "0x1"},
        {"format": OBSERVATION_FORMAT, "capture_id": capture["capture_id"], "sequence": 6,
         "event_kind": "instruction", "runtime_address": "0x7031de60"},
    ]
    return graphs[0], graph_sha, identity, identity_bytes, capture, observations


def _correlate(graph=None, capture=None, observations=None):
    default_graph, graph_sha, identity, identity_bytes, default_capture, default_observations = _inputs()
    graph = default_graph if graph is None else graph
    capture = default_capture if capture is None else capture
    observations = default_observations if observations is None else observations
    return correlate_runtime_addresses(
        graph,
        graph_sha256=graph_sha,
        static_identity=identity,
        static_identity_sha256=hashlib.sha256(identity_bytes).hexdigest(),
        capture=capture,
        capture_sha256=hashlib.sha256((json.dumps(capture, sort_keys=True) + "\n").encode()).hexdigest(),
        observations=observations,
        observations_sha256=hashlib.sha256(
            ("\n".join(json.dumps(row, sort_keys=True) for row in observations) + "\n").encode()
        ).hexdigest(),
    )


def test_runtime_address_correlation_normalizes_aslr_and_keeps_sampling_gaps() -> None:
    graph, _, identity, _, capture, observations = _inputs()
    Draft202012Validator.check_schema(SCHEMAS["runtime-static-identity-v1.schema.json"])
    Draft202012Validator.check_schema(SCHEMAS["runtime-capture-manifest-v1.schema.json"])
    Draft202012Validator.check_schema(SCHEMAS["runtime-address-observation-v1.schema.json"])
    Draft202012Validator(SCHEMAS["runtime-static-identity-v1.schema.json"]).validate(identity)
    Draft202012Validator(SCHEMAS["runtime-capture-manifest-v1.schema.json"]).validate(capture)
    for row in observations:
        Draft202012Validator(SCHEMAS["runtime-address-observation-v1.schema.json"]).validate(row)
    original_capture = copy.deepcopy(capture)
    report = _correlate(capture=capture, observations=observations)
    assert capture == original_capture
    Draft202012Validator.check_schema(SCHEMAS["runtime-static-correlation-v1.schema.json"])
    Draft202012Validator(SCHEMAS["runtime-static-correlation-v1.schema.json"]).validate(report)
    assert report["address_mapping"] == {
        "method": "runtime_address_minus_module_delta",
        "runtime_module_base": "0x70000000",
        "static_image_base": "0x10000",
        "module_delta": "0x6fff0000",
    }
    assert report["sampling"]["gaps"] == [{
        "first_sequence": 5, "last_sequence": 5, "reason": "synthetic dropped event",
    }]
    assert report["summary"] == {
        "event_count": 6,
        "matched_count": 4,
        "ambiguous_count": 0,
        "unmatched_count": 1,
        "mapping_underflow_count": 1,
        "mapping_overflow_count": 0,
    }
    first = report["events"][0]
    expected = next(
        node for node in graph["nodes"]
        if node.get("kind") == "operation" and node.get("operation_address") == "0032de44"
    )
    assert first["normalized_address"] == "0x32de44"
    assert first["matched_node_ids"] == [expected["id"]]
    assert first["function_entries"] == ["0032ddee"]
    assert report["events"][4]["match_state"] == "mapping_underflow"


def test_runtime_static_identity_mismatches_fail_closed() -> None:
    _, _, _, _, capture, _ = _inputs()
    capture = copy.deepcopy(capture)
    capture["program_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="runtime/static program_sha256 mismatch"):
        _correlate(capture=capture)

    graph, graph_sha, identity, identity_bytes, capture, observations = _inputs()
    identity = copy.deepcopy(identity)
    identity["semantic_graph_sha256"] = "0" * 64
    identity_bytes = (json.dumps(identity, sort_keys=True) + "\n").encode()
    capture = copy.deepcopy(capture)
    capture["static_identity_sha256"] = hashlib.sha256(identity_bytes).hexdigest()
    with pytest.raises(ValueError, match="static identity does not pin"):
        correlate_runtime_addresses(
            graph,
            graph_sha256=graph_sha,
            static_identity=identity,
            static_identity_sha256=hashlib.sha256(identity_bytes).hexdigest(),
            capture=capture,
            capture_sha256=hashlib.sha256((json.dumps(capture, sort_keys=True) + "\n").encode()).hexdigest(),
            observations=observations,
            observations_sha256="a" * 64,
        )


def test_module_mapping_address_overflow_remains_explicit() -> None:
    _, _, _, _, capture, observations = _inputs()
    capture = copy.deepcopy(capture)
    capture["runtime_module_base"] = "0x0"
    observations = copy.deepcopy(observations)
    observations[0]["runtime_address"] = "0xffffffffffffffff"
    report = _correlate(capture=capture, observations=observations)
    Draft202012Validator(SCHEMAS["runtime-static-correlation-v1.schema.json"]).validate(report)
    assert report["events"][0]["match_state"] == "mapping_overflow"
    assert report["events"][0]["normalized_address"] is None


def test_runtime_sequence_gaps_must_be_declared_and_not_observed() -> None:
    _, _, _, _, capture, _ = _inputs()
    capture = copy.deepcopy(capture)
    capture["sampling_gaps"] = []
    capture["sampling_status"] = "unknown"
    with pytest.raises(ValueError, match="sequence gap is not declared"):
        _correlate(capture=capture)

    _, _, _, _, capture, observations = _inputs()
    observations = copy.deepcopy(observations)
    observations.append({
        "format": OBSERVATION_FORMAT,
        "capture_id": capture["capture_id"],
        "sequence": 5,
        "event_kind": "instruction",
        "runtime_address": "0x7032de60",
    })
    with pytest.raises(ValueError, match="sampling gap overlaps"):
        _correlate(observations=observations)


def test_duplicate_static_operation_address_is_reported_ambiguous() -> None:
    graph, graph_sha, identity, identity_bytes, capture, observations = _inputs()
    graph = copy.deepcopy(graph)
    original = next(
        node for node in graph["nodes"]
        if node.get("kind") == "operation" and node.get("operation_address") == "0032de44"
    )
    duplicate = copy.deepcopy(original)
    duplicate["id"] = "operation:" + "f" * 64
    graph["nodes"].append(duplicate)
    report = correlate_runtime_addresses(
        graph, graph_sha256=graph_sha, static_identity=identity,
        static_identity_sha256=hashlib.sha256(identity_bytes).hexdigest(), capture=capture,
        capture_sha256=hashlib.sha256((json.dumps(capture, sort_keys=True) + "\n").encode()).hexdigest(),
        observations=observations, observations_sha256="a" * 64,
    )
    assert report["events"][0]["match_state"] == "ambiguous"
    assert report["events"][0]["matched_node_ids"] == sorted([original["id"], duplicate["id"]])


def test_runtime_correlation_cli_writes_schema_valid_report(tmp_path: Path, capsys) -> None:
    graph, _, identity, _, capture, observations = _inputs()
    identity_path = tmp_path / "identity.json"
    identity_path.write_text(json.dumps(identity, sort_keys=True) + "\n", encoding="utf-8")
    capture_path = tmp_path / "capture.json"
    capture_path.write_text(json.dumps(capture, sort_keys=True) + "\n", encoding="utf-8")
    observations_path = tmp_path / "observations.jsonl"
    observations_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in observations), encoding="utf-8",
    )
    output = tmp_path / "correlation.json"
    assert main([
        str(GRAPH_PATH), str(identity_path), str(capture_path), str(observations_path),
        "--output", str(output),
    ]) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    Draft202012Validator(SCHEMAS["runtime-static-correlation-v1.schema.json"]).validate(report)
    assert report["summary"]["matched_count"] == 4
    assert "runtime events: 6" in capsys.readouterr().out


def test_pinned_runtime_correlation_replay_and_benchmark(tmp_path: Path) -> None:
    replay = json.loads((REPLAY_DIR / "replay-manifest.json").read_text(encoding="utf-8"))
    assert replay["input_origin"].startswith("real installed Nevergone binary and static graph; synthetic runtime")
    assert "no game runtime PC events" in replay["input_origin"]
    for artifact in replay["artifacts"]:
        raw = (REPLAY_DIR / artifact["path"]).resolve().read_bytes()
        assert len(raw) == artifact["bytes"]
        assert hashlib.sha256(raw).hexdigest() == artifact["sha256"]

    manifest = json.loads((REPLAY_DIR / "benchmark-manifest.json").read_text(encoding="utf-8"))
    for contract in manifest["schemas"].values():
        contract["path"] = str((REPLAY_DIR / contract["path"]).resolve())
    for artifact_id, artifact in manifest["artifacts"].items():
        if artifact["role"] == "input":
            artifact["path"] = str((REPLAY_DIR / artifact["path"]).resolve())
        else:
            artifact["path"] = str(tmp_path / "correlation.generated.json")
    manifest_path = tmp_path / "benchmark-manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    summary, code = run_benchmark(manifest_path, mode="smoke", output_path=tmp_path / "summary.json")

    assert code == 0
    assert summary["status"] == "passed"
    generated = tmp_path / "correlation.generated.json"
    assert generated.read_bytes() == (REPLAY_DIR / "correlation.json").read_bytes()
    assert [metric["value"] for metric in summary["metrics"]] == [6, 4, 1]


def test_pinned_device_runtime_capture_replay_preserves_unknown_sampling(tmp_path: Path) -> None:
    replay = json.loads((DEVICE_RUNTIME_REPLAY_DIR / "replay-manifest.json").read_text(encoding="utf-8"))
    for artifact in replay["artifacts"]:
        raw = (DEVICE_RUNTIME_REPLAY_DIR / artifact["path"]).resolve().read_bytes()
        assert len(raw) == artifact["bytes"]
        assert hashlib.sha256(raw).hexdigest() == artifact["sha256"]

    capture = json.loads((DEVICE_RUNTIME_REPLAY_DIR / "capture-manifest.json").read_text(encoding="utf-8"))
    assert capture["sampling_status"] == "unknown"
    assert capture["sampling_gaps"] == []
    observations_path = DEVICE_RUNTIME_REPLAY_DIR / "observations.jsonl"
    observations, _ = _read_jsonl(observations_path)
    assert len(observations) == 88
    assert all(row["event_kind"] == "function_entry" for row in observations)

    output = tmp_path / "device-correlation.json"
    assert main([
        str(RUNTIME_GRAPH_PATH),
        str(DEVICE_RUNTIME_STATIC_IDENTITY_PATH),
        str(DEVICE_RUNTIME_REPLAY_DIR / "capture-manifest.json"),
        str(observations_path),
        "--output", str(output),
    ]) == 0
    generated = json.loads(output.read_text(encoding="utf-8"))
    expected = json.loads((DEVICE_RUNTIME_REPLAY_DIR / "correlation.json").read_text(encoding="utf-8"))
    Draft202012Validator(SCHEMAS["runtime-static-correlation-v1.schema.json"]).validate(generated)
    assert generated == expected
    assert generated["summary"] == {
        "event_count": 88,
        "matched_count": 88,
        "ambiguous_count": 0,
        "unmatched_count": 0,
        "mapping_underflow_count": 0,
        "mapping_overflow_count": 0,
    }
    assert {row["normalized_address"] for row in generated["events"]} == {"0x544a60", "0x2d2f1c"}
    assert {row["match_state"] for row in generated["events"]} == {"matched"}
