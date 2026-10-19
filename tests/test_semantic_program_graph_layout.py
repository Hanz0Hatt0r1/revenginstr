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
from revenginstr.semantic_program_query import query_graphs
from revenginstr.semantic_program_graph_evaluation import evaluate_semantic_program_graph

ROOT = Path(__file__).resolve().parents[1]


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
