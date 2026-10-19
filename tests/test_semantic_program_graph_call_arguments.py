from __future__ import annotations

import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator
import pytest

from revenginstr.semantic_program_graph import (
    FORMAT_V4,
    _read_jsonl,
    build_semantic_program_graphs,
    validate_graph_references,
)
from revenginstr.semantic_program_query import query_graphs
from revenginstr.semantic_program_path_query import query_graphs as query_paths
from revenginstr.runtime_static_correlation import correlate_runtime_addresses

ROOT = Path(__file__).resolve().parents[1]
REPLAY = ROOT / (
    "docs/evidence/semantic-program-graph-v4/"
    "nevergone-runtime-call-arguments-20261020"
)


def _validator(name: str) -> Draft202012Validator:
    schema = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def test_v4_joins_call_arguments_to_exact_resolved_call_sites() -> None:
    manifest = json.loads((REPLAY / "replay-manifest.json").read_text(encoding="utf-8"))
    for artifact in manifest["artifacts"]:
        raw = (REPLAY / artifact["path"]).resolve().read_bytes()
        assert len(raw) == artifact["bytes"]
        assert hashlib.sha256(raw).hexdigest() == artifact["sha256"]

    effects_path = ROOT / (
        "docs/evidence/semantic-program-graph-v3/"
        "nevergone-runtime-correlation-20261020/function-effects.jsonl"
    )
    layout_path = ROOT / (
        "docs/evidence/semantic-program-graph-v3/"
        "nevergone-ccjoystick/type-layout-hypothesis.jsonl"
    )
    observations_path = REPLAY / "call-arguments.jsonl"
    graph_path = REPLAY / "semantic-program-graph.jsonl"
    effects, effects_sha256 = _read_jsonl(effects_path)
    layouts, layout_sha256 = _read_jsonl(layout_path)
    observations, observations_sha256 = _read_jsonl(observations_path)
    graphs, graph_sha256 = _read_jsonl(graph_path)

    assert len(graphs) == 1
    graph = graphs[0]
    assert graph["format"] == FORMAT_V4
    assert graph["source_call_arguments_sha256"] == observations_sha256
    assert graph["source_call_arguments_program_sha256"] == manifest["program_sha256"]
    _validator("semantic-program-graph-v4.schema.json").validate(graph)
    observation_validator = _validator("direct-call-argument-observation-v1.schema.json")
    for row in observations:
        observation_validator.validate(row)

    rebuilt = build_semantic_program_graphs(
        effects,
        source_sha256=effects_sha256,
        type_layout_rows=layouts,
        type_layout_sha256=layout_sha256,
        call_argument_rows=observations,
        call_argument_sha256=observations_sha256,
    )[0]
    assert (json.dumps(rebuilt, sort_keys=True) + "\n").encode() == graph_path.read_bytes()

    annotated = [
        node for node in graph["nodes"]
        if "call_argument_observation_record_index" in node
    ]
    assert len(annotated) == manifest["summary"]["call_argument_observations"] == 36
    assert sum(node["call_argument_count"] for node in annotated) == 70
    assert sum(
        argument["value_token"].startswith("const:")
        for node in annotated for argument in node["call_arguments"]
    ) == 10
    assert all(
        node["call_argument_source_evidence_ref"]
        == next(
            row["evidence_ref"] for row in observations
            if row["caller_entry"] == node["function_entry"]
            and row["call_address"] == node["operation_address"]
        )
        for node in annotated
    )

    query = query_graphs(
        graphs,
        source_sha256=graph_sha256,
        view="accepted-high-confidence",
        kinds=["operation"],
        relations=["calls"],
        function_entries=["002d2f1c", "00544a60"],
    )[0]
    _validator("semantic-program-query-result-v1.schema.json").validate(query)
    queried = [
        node for node in query["nodes"]
        if node["kind"] == "operation"
        and "call_argument_observation_record_index" in node
    ]
    assert len(queried) == 36

    constant_query = query_graphs(
        graphs,
        source_sha256=graph_sha256,
        view="exact-only",
        kinds=["operation"],
        relations=["calls"],
        call_argument_tokens=["const:0x0:4"],
    )[0]
    _validator("semantic-program-query-result-v1.schema.json").validate(constant_query)
    assert constant_query["filters"]["call_argument_tokens"] == ["const:0x0:4"]
    assert constant_query["nodes"]
    assert all(
        any(argument["value_token"] == "const:0x0:4" for argument in node["call_arguments"])
        for node in constant_query["nodes"]
    )

    path_query = query_paths(
        graphs,
        source_sha256=graph_sha256,
        source_function_entry="002d2f1c",
        target_function_entry="00544c30",
        view="exact-only",
    )[0]
    _validator("semantic-program-path-query-result-v1.schema.json").validate(path_query)
    assert path_query["source_graph_format"] == FORMAT_V4
    assert path_query["status"] == "direct_call_paths_found"
    assert len(path_query["paths"]) == 1

    runtime_dir = ROOT / "docs/evidence/runtime-static-correlation-v1/nevergone-device-runtime-20261019"
    identity = json.loads((runtime_dir / "static-identity.json").read_text(encoding="utf-8"))
    identity["semantic_graph_sha256"] = graph_sha256
    identity_bytes = (json.dumps(identity, sort_keys=True) + "\n").encode()
    capture = json.loads((runtime_dir / "capture-manifest.json").read_text(encoding="utf-8"))
    capture["static_identity_sha256"] = hashlib.sha256(identity_bytes).hexdigest()
    capture_bytes = (json.dumps(capture, sort_keys=True) + "\n").encode()
    runtime_observations, runtime_observations_sha256 = _read_jsonl(runtime_dir / "observations.jsonl")
    runtime_report = correlate_runtime_addresses(
        graph,
        graph_sha256=graph_sha256,
        static_identity=identity,
        static_identity_sha256=hashlib.sha256(identity_bytes).hexdigest(),
        capture=capture,
        capture_sha256=hashlib.sha256(capture_bytes).hexdigest(),
        observations=runtime_observations,
        observations_sha256=runtime_observations_sha256,
    )
    assert runtime_report["summary"]["event_count"] == 88
    assert runtime_report["summary"]["matched_count"] == 88

    malformed_graph = json.loads(json.dumps(graph))
    annotated_node = next(
        node for node in malformed_graph["nodes"]
        if "call_argument_observation_record_index" in node
    )
    del annotated_node["call_arguments"]
    with pytest.raises(ValueError, match="must include all provenance and value fields"):
        validate_graph_references(malformed_graph)

    mismatched = [dict(row) for row in observations]
    mismatched[0] = {**mismatched[0], "callee_entry": "ffffffff"}
    with pytest.raises(ValueError, match="does not match one exact resolved CALL site"):
        build_semantic_program_graphs(
            effects,
            source_sha256=effects_sha256,
            type_layout_rows=layouts,
            type_layout_sha256=layout_sha256,
            call_argument_rows=mismatched,
            call_argument_sha256=observations_sha256,
        )

    wrong_build = [{**row, "program_sha256": "0" * 64} for row in observations]
    with pytest.raises(ValueError, match="does not match type-layout program_sha256"):
        build_semantic_program_graphs(
            effects,
            source_sha256=effects_sha256,
            type_layout_rows=layouts,
            type_layout_sha256=layout_sha256,
            call_argument_rows=wrong_build,
            call_argument_sha256=observations_sha256,
        )

    malformed_graph = json.loads(json.dumps(graph))
    multi_argument_node = next(
        node for node in malformed_graph["nodes"]
        if "call_argument_observation_record_index" in node
        and len(node["call_arguments"]) > 1
    )
    multi_argument_node["call_arguments"][1]["index"] = True
    with pytest.raises(ValueError, match="call-argument list is malformed"):
        validate_graph_references(malformed_graph)
