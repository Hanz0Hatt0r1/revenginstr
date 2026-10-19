from __future__ import annotations

import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator
import pytest

from revenginstr.semantic_program_graph import (
    FORMAT_V3,
    _read_jsonl,
    build_semantic_program_graphs,
)
from revenginstr.semantic_program_query import _in_view, query_graphs
from revenginstr.semantic_program_graph_evaluation import evaluate_semantic_program_graph

ROOT = Path(__file__).resolve().parents[1]


def test_accepted_view_includes_exact_uncontested_rows_without_confidence() -> None:
    assert _in_view({
        "evidence_class": "exact_static",
        "confidence": None,
        "conflict_state": "uncontested",
    }, "accepted-high-confidence", 0.95)
    assert not _in_view({
        "evidence_class": "exact_static",
        "confidence": None,
        "conflict_state": "contested",
    }, "accepted-high-confidence", 0.95)
    assert not _in_view({
        "evidence_class": "derived_structural",
        "confidence": None,
        "conflict_state": "uncontested",
    }, "accepted-high-confidence", 0.95)
    assert _in_view({
        "evidence_class": "derived_structural",
        "confidence": 0.95,
        "conflict_state": "uncontested",
    }, "accepted-high-confidence", 0.95)
    assert not _in_view({
        "evidence_class": "derived_structural",
        "confidence": 0.94,
        "conflict_state": "uncontested",
    }, "accepted-high-confidence", 0.95)


def _schema(name: str) -> Draft202012Validator:
    schema = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def test_nevergone_layout_joins_graph_and_remains_queryable(tmp_path: Path) -> None:
    replay_manifest = ROOT / (
        "docs/evidence/semantic-program-graph-v3/nevergone-ccjoystick/manifest.json"
    )
    for artifact in json.loads(replay_manifest.read_text(encoding="utf-8"))["artifacts"]:
        raw = (ROOT / artifact["path"]).read_bytes()
        assert len(raw) == artifact["bytes"]
        assert hashlib.sha256(raw).hexdigest() == artifact["sha256"]

    effects_path = ROOT / (
        "docs/evidence/semantic-program-graph-evaluation/"
        "nevergone-player-horizontal-facing/nevergone-facing-effects.jsonl"
    )
    layout_path = ROOT / (
        "docs/evidence/semantic-program-graph-v3/nevergone-ccjoystick/"
        "type-layout-hypothesis.jsonl"
    )
    graph_path = ROOT / (
        "docs/evidence/semantic-program-graph-v3/nevergone-ccjoystick/"
        "semantic-program-graph.jsonl"
    )
    query_path = ROOT / (
        "docs/evidence/semantic-program-graph-v3/nevergone-ccjoystick/"
        "field-104-query.jsonl"
    )
    effects, effects_sha256 = _read_jsonl(effects_path)
    layout_rows, layout_sha256 = _read_jsonl(layout_path)

    graph = build_semantic_program_graphs(
        effects,
        source_sha256=effects_sha256,
        type_layout_rows=layout_rows,
        type_layout_sha256=layout_sha256,
    )[0]

    assert graph["format"] == FORMAT_V3
    assert graph["source_type_layout_hypotheses_sha256"] == layout_sha256
    type_node = next(node for node in graph["nodes"] if node["kind"] == "type")
    assert type_node["object_size"]["exact_size_bytes"] == 340
    fields = [node for node in graph["nodes"] if node["kind"] == "layout_field"]
    assert len(fields) == 13
    sprite_field = next(node for node in fields if node["offset_bytes"] == 260)
    assert sprite_field["type_candidates"][0]["target_type_id"] == "cocos2d::CCSprite"
    assert sprite_field["conflict_state"] == "uncontested"

    _schema("semantic-program-graph-v3.schema.json").validate(graph)
    graph_bytes = (json.dumps(graph, sort_keys=True) + "\n").encode()
    assert graph_bytes == graph_path.read_bytes()
    result = query_graphs(
        [graph],
        source_sha256=hashlib.sha256(graph_path.read_bytes()).hexdigest(),
        kinds=["layout_field"],
        field_offsets=["0x104"],
        type_ids=["nevergone:opaque-object-002a6584"],
    )[0]
    assert len(result["nodes"]) == 1
    assert result["nodes"][0]["offset_bytes"] == 260
    assert [node["kind"] for node in result["related_nodes"]] == ["type"]
    _schema("semantic-program-query-result-v1.schema.json").validate(result)
    assert (json.dumps(result, sort_keys=True) + "\n").encode() == query_path.read_bytes()

    type_node = next(node for node in graph["nodes"] if node["kind"] == "type")
    gold = {
        "format": "REVENGINSTR.SemanticProgramGraphGold/1",
        "subgraph_id": "nevergone-joystick-field-membership",
        "dataset_id": "synthetic-graph-layout-contract",
        "split_id": "schema-replay-v1",
        "program_id": graph["program_id"],
        "graph_id": graph["graph_id"],
        "scope_node_ids": [type_node["id"], sprite_field["id"]],
        "complete_relations": ["has_field"],
        "edges": [{
            "from": type_node["id"],
            "to": sprite_field["id"],
            "relation": "has_field",
            "evidence_refs": [{
                "artifact_sha256": "f" * 64,
                "record_index": 1,
                "source_format": "SyntheticIndependentLayoutAdjudication/1",
            }],
        }],
        "adjudication_status": "adjudicated",
    }
    _schema("semantic-program-graph-gold-v1.schema.json").validate(gold)
    graph_gold_path = tmp_path / "gold.jsonl"
    graph_gold_path.write_text(json.dumps(gold) + "\n", encoding="utf-8")
    evaluation = evaluate_semantic_program_graph(
        graph_path, graph_gold_path, view="exploratory"
    )
    assert evaluation["per_relation"]["has_field"]["candidate_edge_precision"] == 1
    assert evaluation["per_relation"]["has_field"]["recall"] == 1
    _schema("semantic-program-graph-evaluation-v1.schema.json").validate(evaluation)

    wrong_program = dict(layout_rows[0], program_id="another-program")
    with pytest.raises(ValueError, match="program_id is absent"):
        build_semantic_program_graphs(
            effects,
            source_sha256=effects_sha256,
            type_layout_rows=[wrong_program],
            type_layout_sha256=layout_sha256,
        )

    duplicate_field = json.loads(json.dumps(layout_rows[0]))
    duplicate_field["fields"].append(dict(duplicate_field["fields"][0]))
    with pytest.raises(ValueError, match="duplicate offset_bytes"):
        build_semantic_program_graphs(
            effects,
            source_sha256=effects_sha256,
            type_layout_rows=[duplicate_field],
            type_layout_sha256=layout_sha256,
        )


def test_nevergone_runtime_resource_calls_match_independent_instruction_references() -> None:
    replay_dir = ROOT / (
        "docs/evidence/semantic-program-graph-evaluation/"
        "nevergone-runtime-resource-loader-20261020"
    )
    replay = json.loads((replay_dir / "replay-manifest.json").read_text(encoding="utf-8"))
    for artifact in replay["artifacts"]:
        raw = (replay_dir / artifact["path"]).resolve().read_bytes()
        assert len(raw) == artifact["bytes"]
        assert hashlib.sha256(raw).hexdigest() == artifact["sha256"]

    crosscheck_path = replay_dir / "direct-call-crosscheck.jsonl"
    crosscheck_rows = [
        json.loads(line) for line in crosscheck_path.read_text(encoding="utf-8").splitlines()
    ]
    crosscheck_validator = _schema(
        "semantic-program-graph-call-reference-crosscheck-v1.schema.json"
    )
    artifact_hashes = {artifact["id"]: artifact["sha256"] for artifact in replay["artifacts"]}
    for row in crosscheck_rows:
        crosscheck_validator.validate(row)
        assert row["status"] == "exact_match"
        assert row["program_sha256"] == replay["program_sha256"]
        assert row["instruction_export_sha256"] == replay["instruction_export_source"]["sha256"]
        assert row["graph_sha256"] == artifact_hashes["semantic_graph"]
        pcode_artifact = (
            "LoadGameLevels_pcode"
            if row["function_entry"] == "002d2f1c"
            else "CCFileUtils_getFileData_pcode"
        )
        assert row["pcode_flow_sha256"] == artifact_hashes[pcode_artifact]

    gold_path = replay_dir / "gold-subgraphs.jsonl"
    gold = json.loads(gold_path.read_text(encoding="utf-8"))
    _schema("semantic-program-graph-gold-v1.schema.json").validate(gold)
    assert len(crosscheck_rows) == len(gold["edges"]) == 36
    crosscheck_sha256 = hashlib.sha256(crosscheck_path.read_bytes()).hexdigest()
    assert all(
        reference["artifact_sha256"] == crosscheck_sha256
        for edge in gold["edges"] for reference in edge["evidence_refs"]
    )
    assert {row["function_entry"] for row in crosscheck_rows} == {"002d2f1c", "00544a60"}
    assert [sum(row["function_entry"] == entry for row in crosscheck_rows)
            for entry in ("002d2f1c", "00544a60")] == [9, 27]

    graph_path = ROOT / (
        "docs/evidence/semantic-program-graph-v3/nevergone-runtime-correlation-20261020/"
        "semantic-program-graph.jsonl"
    )
    evaluation = evaluate_semantic_program_graph(graph_path, gold_path, view="exact-only")
    checked_in = json.loads((replay_dir / "evaluation.json").read_text(encoding="utf-8"))
    assert evaluation == checked_in
    _schema("semantic-program-graph-evaluation-v1.schema.json").validate(evaluation)
    calls = evaluation["per_relation"]["calls"]
    assert calls["candidate_edges"] == calls["gold_edges"] == calls["true_positives"] == 36
    assert calls["candidate_edge_precision"] == calls["recall"] == 1.0
    assert evaluation["unsupported_edge_count"] == 0
    assert evaluation["provenance_completeness"] == 1.0
    assert evaluation["accepted_edge_count"] == 36
    assert evaluation["accepted_edge_true_positives"] == 36
    assert evaluation["accepted_edge_precision"] == 1.0

    graph_rows, graph_sha256 = _read_jsonl(graph_path)
    accepted_query = query_graphs(
        graph_rows,
        source_sha256=graph_sha256,
        view="accepted-high-confidence",
        relations=["calls"],
    )[0]
    graph_nodes = {node["id"]: node for node in graph_rows[0]["nodes"]}
    accepted_calls = {
        (
            graph_nodes[edge["from"]]["function_entry"],
            graph_nodes[edge["from"]]["operation_address"],
            graph_nodes[edge["to"]]["entry"],
        )
        for edge in accepted_query["edges"]
    }
    crosschecked_calls = {
        (row["function_entry"], row["operation_address"], row["target_entry"])
        for row in crosscheck_rows
    }
    assert crosschecked_calls <= accepted_calls
    assert all(edge["confidence"] is None for edge in accepted_query["edges"])
