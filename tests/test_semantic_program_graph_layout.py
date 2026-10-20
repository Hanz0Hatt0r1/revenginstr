from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator
import pytest

from revenginstr.effect_ir import build_function_effect_ir
from revenginstr.semantic_program_graph import (
    FORMAT_V3,
    _read_jsonl,
    build_semantic_program_graphs,
)
from revenginstr.semantic_program_query import _in_view, query_graphs
from revenginstr.semantic_program_graph_evaluation import evaluate_semantic_program_graph
from revenginstr.type_layout_builder import build_type_layout_hypotheses

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


def test_nevergone_member_map_joins_function_fields_to_reviewed_layout(tmp_path: Path) -> None:
    replay_dir = ROOT / (
        "docs/evidence/semantic-program-graph-v3/"
        "nevergone-ccjoystick-init-layout-join-20261020"
    )
    manifest = json.loads((replay_dir / "replay-manifest.json").read_text(encoding="utf-8"))
    for artifact in manifest["artifacts"]:
        raw = (replay_dir / artifact["path"]).resolve().read_bytes()
        assert len(raw) == artifact["bytes"]
        assert hashlib.sha256(raw).hexdigest() == artifact["sha256"]

    effects_path = ROOT / (
        "docs/evidence/receiver-field-access/"
        "nevergone-ccjoystick-init-20261019/function-effects.jsonl"
    )
    review_dir = ROOT / "docs/evidence/type-layout-review/nevergone-ccjoystick-20261019"
    layout_path = review_dir / "type-layout-hypothesis.jsonl"
    member_map_path = review_dir / "member-map.jsonl"
    graph_path = replay_dir / "semantic-program-graph.jsonl"
    query_path = replay_dir / "field-access-query.jsonl"
    effects, effects_sha256 = _read_jsonl(effects_path)
    layouts, layout_sha256 = _read_jsonl(layout_path)
    member_maps, member_map_sha256 = _read_jsonl(member_map_path)

    graph = build_semantic_program_graphs(
        effects,
        source_sha256=effects_sha256,
        type_layout_rows=layouts,
        type_layout_sha256=layout_sha256,
        type_layout_member_map_rows=member_maps,
        type_layout_member_map_sha256=member_map_sha256,
    )[0]
    _schema("semantic-program-graph-v3.schema.json").validate(graph)
    assert graph["program_id"] == "nevergone:libcocos2dcpp.so"
    assert graph["source_type_layout_member_maps_sha256"] == member_map_sha256
    joined_edges = [
        edge for edge in graph["edges"]
        if edge["relation"] == "has_field" and edge["to"].startswith("field:")
    ]
    assert len(joined_edges) == 9
    assert all(
        any(
            support.get("provenance", {}).get("source_format") == "REVENGINSTR.TypeLayoutMemberMap/1"
            and support.get("provenance", {}).get("artifact_sha256") == member_map_sha256
            for support in edge["support"]
        )
        for edge in joined_edges
    )
    graph_bytes = (json.dumps(graph, sort_keys=True) + "\n").encode()
    assert graph_bytes == graph_path.read_bytes()

    result = query_graphs(
        [graph],
        source_sha256=hashlib.sha256(graph_path.read_bytes()).hexdigest(),
        view="exploratory",
        kinds=["field"],
        function_entries=["002a6584"],
        relations=["has_field"],
        field_offsets=["0x119", "0x11a"],
    )[0]
    _schema("semantic-program-query-result-v1.schema.json").validate(result)
    assert {node["field_offset"] for node in result["nodes"]} == {"0x119", "0x11a"}
    assert [node["kind"] for node in result["related_nodes"]] == ["type"]
    assert len(result["edges"]) == 2
    assert (json.dumps(result, sort_keys=True) + "\n").encode() == query_path.read_bytes()

    type_node_id = joined_edges[0]["from"]
    # Exercise the gold/evaluator endpoint contract only. The member map also
    # built these graph edges, so this is not an independent accuracy result.
    gold = {
        "format": "REVENGINSTR.SemanticProgramGraphGold/1",
        "subgraph_id": "nevergone-member-map-endpoint-contract",
        "dataset_id": "member-map-contract-smoke",
        "split_id": "construction-input-not-independent-gold",
        "program_id": graph["program_id"],
        "graph_id": graph["graph_id"],
        "scope_node_ids": [type_node_id, *sorted(edge["to"] for edge in joined_edges)],
        "complete_relations": ["has_field"],
        "edges": [
            {
                "from": type_node_id,
                "to": edge["to"],
                "relation": "has_field",
                "evidence_refs": [{
                    "artifact_sha256": member_map_sha256,
                    "record_index": 1,
                    "source_format": "REVENGINSTR.TypeLayoutMemberMap/1",
                }],
            }
            for edge in joined_edges
        ],
        "adjudication_status": "adjudicated",
    }
    _schema("semantic-program-graph-gold-v1.schema.json").validate(gold)
    gold_path = tmp_path / "member-map-gold-contract.jsonl"
    gold_path.write_text(json.dumps(gold) + "\n", encoding="utf-8")
    evaluation = evaluate_semantic_program_graph(
        graph_path, gold_path, view="exploratory",
    )
    assert evaluation["per_relation"]["has_field"]["candidate_edges"] == 9

    wrong_map = [{**member_maps[0], "program_sha256": "0" * 64}]
    with pytest.raises(ValueError, match="program_sha256 does not match type-layout hypothesis"):
        build_semantic_program_graphs(
            effects,
            source_sha256=effects_sha256,
            type_layout_rows=layouts,
            type_layout_sha256=layout_sha256,
            type_layout_member_map_rows=wrong_map,
            type_layout_member_map_sha256=member_map_sha256,
        )


def test_nevergone_ccjoystick_method_pair_replay_is_reproducible() -> None:
    replay_dir = ROOT / (
        "docs/evidence/semantic-program-graph-v3/"
        "nevergone-ccjoystick-method-pair-20261020"
    )
    manifest = json.loads((replay_dir / "replay-manifest.json").read_text(encoding="utf-8"))
    for artifact in manifest["artifacts"]:
        raw = (replay_dir / artifact["path"]).resolve().read_bytes()
        assert len(raw) == artifact["bytes"]
        assert hashlib.sha256(raw).hexdigest() == artifact["sha256"]

    program_id = "nevergone:libcocos2dcpp.so"
    update_loads = replay_dir / "update-touchpoint-loads.tsv"
    update_stores = replay_dir / "update-touchpoint-memory-stores.jsonl"
    update_effects = build_function_effect_ir(
        program_id,
        parameter_load_tsv=update_loads,
        memory_store_access_jsonl=update_stores,
    )
    update_effects_bytes = "".join(
        json.dumps(record, sort_keys=True) + "\n" for record in update_effects
    ).encode()
    assert update_effects_bytes == (replay_dir / "update-touchpoint-effects.jsonl").read_bytes()
    [update_record] = update_effects
    assert update_record["function_entry"] == "002a5f00"
    assert len(update_record["effects"]) == 14
    writes = [effect for effect in update_record["effects"] if effect["kind"] == "parameter_field_write"]
    assert {(effect["field_offset"], effect["value_size"]) for effect in writes} == {
        ("0x13c", 4), ("0x140", 4),
    }
    assert all(
        effect["source_parameter_index"] is None
        and effect["provenance"]["source_format"] == "REVENGINSTR.GhidraMemoryStoreAccess/1"
        for effect in writes
    )

    memory_store_schema = _schema("ghidra-memory-store-access-v1.schema.json")
    memory_rows = [
        json.loads(line)
        for line in update_stores.read_text(encoding="utf-8").splitlines()
    ]
    pcode_path = replay_dir / "update-touchpoint-pcode-flow.tsv"
    pcode_rows = list(csv.DictReader(pcode_path.open(encoding="utf-8"), delimiter="\t"))
    pcode_schema = _schema("ghidra-function-pcode-flow-v1.schema.json")
    for row in pcode_rows:
        pcode_schema.validate(row)
    pcode_by_key = {
        (row["function_entry"], row["op_address"], row["op_time"], row["opcode"]): row
        for row in pcode_rows
    }
    assert len(pcode_by_key) == len(pcode_rows) == 176
    assert len(memory_rows) == 2
    for row in memory_rows:
        memory_store_schema.validate(row)
        store = pcode_by_key[(row["function_entry"], row["address"], str(row["time"]), "STORE")]
        store_inputs = store["inputs"].split(";")
        assert len(store_inputs) == 3
        assert store_inputs[1] == row["pointer_token"]
        assert int(store_inputs[2].rsplit(":", 1)[1]) == row["memory_width_bytes"]
        expression = {}
        for operation in row["address_expression_ops"]:
            key = (row["function_entry"], operation["address"], str(operation["time"]), operation["opcode"])
            expression[operation["opcode"]] = pcode_by_key[key]
        cast = expression["CAST"]
        ptradd = expression["PTRADD"]
        assert cast["output"] == row["pointer_token"]
        assert cast["inputs"] == ptradd["output"]
        ptradd_inputs = ptradd["inputs"].split(";")
        assert len(ptradd_inputs) == 3
        assert ptradd_inputs[1].startswith("const:")
        assert ptradd_inputs[2].startswith("const:")
        byte_offset = int(ptradd_inputs[1].split(":")[1], 0)
        element_scale = int(ptradd_inputs[2].split(":")[1], 0)
        assert row["offset_bytes"] == byte_offset * element_scale

    load_rows = list(csv.DictReader(update_loads.open(encoding="utf-8"), delimiter="\t"))
    assert len(load_rows) == 12
    for row in load_rows:
        load = pcode_by_key[(row["function_entry"], row["load_address"], row["load_time"], "LOAD")]
        assert int(load["output"].rsplit(":", 1)[1]) == int(row["value_size"])

    init_dir = ROOT / "docs/evidence/receiver-field-access/nevergone-ccjoystick-init-20261019"
    init_effects = build_function_effect_ir(
        program_id,
        parameter_store_tsv=init_dir / "parameter-stores.tsv",
        parameter_load_tsv=init_dir / "parameter-loads.tsv",
    )
    init_bytes = "".join(json.dumps(record, sort_keys=True) + "\n" for record in init_effects).encode()
    assert init_bytes == (init_dir / "function-effects.jsonl").read_bytes()
    combined = sorted(init_effects + update_effects, key=lambda row: (row["program_id"], row["function_entry"]))
    combined_bytes = "".join(json.dumps(record, sort_keys=True) + "\n" for record in combined).encode()
    assert combined_bytes == (replay_dir / "function-effects.jsonl").read_bytes()

    effects, effects_sha256 = _read_jsonl(replay_dir / "function-effects.jsonl")
    layouts, layout_sha256 = _read_jsonl(
        ROOT / "docs/evidence/type-layout-review/nevergone-ccjoystick-20261019/type-layout-hypothesis.jsonl"
    )
    member_maps, member_map_sha256 = _read_jsonl(replay_dir / "type-layout-member-map.jsonl")
    graph = build_semantic_program_graphs(
        effects,
        source_sha256=effects_sha256,
        type_layout_rows=layouts,
        type_layout_sha256=layout_sha256,
        type_layout_member_map_rows=member_maps,
        type_layout_member_map_sha256=member_map_sha256,
    )[0]
    _schema("semantic-program-graph-v3.schema.json").validate(graph)
    assert len(graph["nodes"]) == 61
    assert len(graph["edges"]) == 89
    joined = [
        edge for edge in graph["edges"]
        if edge["relation"] == "has_field" and edge["to"].startswith("field:")
    ]
    assert len(joined) == 15
    assert all(
        any(
            support.get("provenance", {}).get("source_format") == "REVENGINSTR.TypeLayoutMemberMap/1"
            and support.get("provenance", {}).get("artifact_sha256") == member_map_sha256
            for support in edge["support"]
        )
        for edge in joined
    )
    graph_path = replay_dir / "semantic-program-graph.jsonl"
    graph_bytes = (json.dumps(graph, sort_keys=True) + "\n").encode()
    assert graph_bytes == graph_path.read_bytes()

    result = query_graphs(
        [graph],
        source_sha256=hashlib.sha256(graph_path.read_bytes()).hexdigest(),
        view="exploratory",
        kinds=["field"],
        function_entries=["002a6584", "002a5f00"],
        relations=["has_field"],
        field_offsets=["0x104", "0x108", "0x110", "0x114", "0x13c", "0x140"],
    )[0]
    _schema("semantic-program-query-result-v1.schema.json").validate(result)
    assert len(result["nodes"]) == len(result["edges"]) == 10
    assert len(result["related_nodes"]) == 1
    assert {node["kind"] for node in result["related_nodes"]} == {"type"}
    assert (json.dumps(result, sort_keys=True) + "\n").encode() == (
        replay_dir / "field-access-query.jsonl"
    ).read_bytes()

    prototype_artifact = next(
        artifact for artifact in manifest["artifacts"] if artifact["id"] == "function_prototypes"
    )
    prototype_path = (replay_dir / prototype_artifact["path"]).resolve()
    prototype_rows = [
        json.loads(line) for line in prototype_path.read_text(encoding="utf-8").splitlines()
    ]
    prototype_validator = _schema("ghidra-function-prototype-v1.schema.json")
    prototype_by_entry = {}
    for row in prototype_rows:
        prototype_validator.validate(row)
        assert row["program_sha256"] == layouts[0]["program_sha256"]
        assert row["signature_source"] == "ANALYSIS"
        parameter = row["parameters"][0]
        assert parameter["index"] == 0
        assert parameter["type"]["kind"] == "pointer"
        assert parameter["type"]["target_name"] == "CCJoyStick"
        assert row["resolved_entry"] not in prototype_by_entry
        prototype_by_entry[row["resolved_entry"]] = row
    assert {
        entry: row["qualified_name"] for entry, row in prototype_by_entry.items()
    } == {
        "002a6584": "CCJoyStick::init",
        "002a5f00": "CCJoyStick::updateTouchPoint",
    }

    layout = layouts[0]
    layout_offsets = {field["offset_bytes"] for field in layout["fields"]}

    def stable_id(kind: str, identity: list[object]) -> str:
        encoded = json.dumps(identity, ensure_ascii=False, separators=(",", ":"))
        return f"{kind}:{hashlib.sha256(encoded.encode('utf-8')).hexdigest()}"

    type_node_id = stable_id("type", [program_id, layout["type_id"]])
    expected_gold_edges: dict[tuple[str, str], set[tuple[str, int, str]]] = {}
    expected_field_context: dict[tuple[str, str], tuple[str, int]] = {}
    for function in combined:
        entry = function["function_entry"]
        prototype = prototype_by_entry[entry]
        assert prototype["parameters"][0]["type"]["target_name"] == "CCJoyStick"
        for effect in function["effects"]:
            if (
                effect["kind"] not in {"parameter_field_read", "parameter_field_write"}
                or effect["parameter_index"] != 0
                or int(effect["field_offset"], 16) not in layout_offsets
            ):
                continue
            field_node_id = stable_id(
                "field", [program_id, entry, effect["parameter_index"], effect["field_offset"]]
            )
            edge_key = (type_node_id, field_node_id)
            expected_field_context[edge_key] = (entry, int(effect["field_offset"], 16))
            expected_gold_edges.setdefault(edge_key, set()).add((
                effect["provenance"]["artifact_sha256"],
                effect["provenance"]["record_index"],
                effect["provenance"]["source_format"],
            ))
    assert len(expected_gold_edges) == 15

    gold_path = replay_dir / "field-layout-gold.jsonl"
    [gold] = [
        json.loads(line) for line in gold_path.read_text(encoding="utf-8").splitlines()
    ]
    _schema("semantic-program-graph-gold-v1.schema.json").validate(gold)
    assert gold["program_id"] == program_id
    assert gold["graph_id"] == graph["graph_id"]
    assert gold["complete_relations"] == ["has_field"]
    gold_edges = {
        (edge["from"], edge["to"]): edge for edge in gold["edges"]
    }
    assert set(gold_edges) == set(expected_gold_edges)
    assert set(gold["scope_node_ids"]) == {
        type_node_id, *(field_node_id for _, field_node_id in expected_gold_edges)
    }
    assert "REVENGINSTR.TypeLayoutMemberMap/1" not in {
        reference["source_format"]
        for edge in gold["edges"] for reference in edge["evidence_refs"]
    }

    manifest_by_id = {artifact["id"]: artifact for artifact in manifest["artifacts"]}
    source_ids_by_format = {
        "REVENGINSTR.GhidraFunctionPrototype/1": "function_prototypes",
        "REVENGINSTR.TypeLayoutHypothesis/1": "type_layout_hypothesis",
        "REVENGINSTR.GhidraParameterLoadField/1": "init_parameter_loads",
        "REVENGINSTR.GhidraParameterStoreField/1": "init_parameter_stores",
        "REVENGINSTR.GhidraMemoryStoreAccess/1": "update_touchpoint_memory_stores",
    }
    records_by_sha: dict[str, list[dict[str, object]]] = {}
    for artifact_id in set(source_ids_by_format.values()) | {
        "update_touchpoint_loads",
    }:
        artifact = manifest_by_id[artifact_id]
        source_path = (replay_dir / artifact["path"]).resolve()
        if source_path.suffix == ".tsv":
            with source_path.open(encoding="utf-8", newline="") as source_file:
                records = list(csv.DictReader(source_file, delimiter="\t"))
        else:
            records = [
                json.loads(line)
                for line in source_path.read_text(encoding="utf-8").splitlines()
            ]
        records_by_sha[artifact["sha256"]] = records

    prototype_indices = {
        row["resolved_entry"]: index
        for index, row in enumerate(prototype_rows, start=1)
    }
    layout_artifact = manifest_by_id["type_layout_hypothesis"]
    for edge_key, edge in gold_edges.items():
        entry, offset = expected_field_context[edge_key]
        expected_refs = {
            (prototype_artifact["sha256"], prototype_indices[entry],
             "REVENGINSTR.GhidraFunctionPrototype/1"),
            (layout_artifact["sha256"], 1, "REVENGINSTR.TypeLayoutHypothesis/1"),
        }
        expected_refs.update(expected_gold_edges[edge_key])
        actual_refs = {
            (reference["artifact_sha256"], reference["record_index"], reference["source_format"])
            for reference in edge["evidence_refs"]
        }
        assert actual_refs == expected_refs
        for artifact_sha256, record_index, source_format in actual_refs:
            assert source_format in source_ids_by_format
            source_records = records_by_sha[artifact_sha256]
            source_row = source_records[record_index - 1]
            assert source_row["format"] == source_format
            if source_format == "REVENGINSTR.GhidraFunctionPrototype/1":
                assert source_row["resolved_entry"] == entry
                assert source_row["parameters"][0]["type"]["target_name"] == "CCJoyStick"
            elif source_format == "REVENGINSTR.TypeLayoutHypothesis/1":
                assert source_row["type_id"] == layout["type_id"]
                assert offset in {field["offset_bytes"] for field in source_row["fields"]}
            else:
                assert source_row["function_entry"] == entry
                root_field = {
                    "REVENGINSTR.GhidraParameterLoadField/1": "base_parameter_index",
                    "REVENGINSTR.GhidraParameterStoreField/1": "destination_parameter_index",
                    "REVENGINSTR.GhidraMemoryStoreAccess/1": "root_parameter_index",
                }[source_format]
                assert source_row[root_field] == 0 or source_row[root_field] == "0"
                raw_offset = source_row.get(
                    "field_offset", source_row.get("destination_offset")
                )
                if source_format == "REVENGINSTR.GhidraMemoryStoreAccess/1":
                    raw_offset = source_row["offset_bytes"]
                elif isinstance(raw_offset, str):
                    raw_offset = int(raw_offset, 16)
                assert raw_offset == offset

    evaluation = evaluate_semantic_program_graph(
        graph_path, gold_path, view="exploratory",
    )
    pinned_evaluation = json.loads(
        (replay_dir / "field-layout-evaluation.json").read_text(encoding="utf-8")
    )
    _schema("semantic-program-graph-evaluation-v1.schema.json").validate(evaluation)
    assert evaluation == pinned_evaluation
    assert evaluation["candidate_edge_count"] == 15
    assert evaluation["per_relation"]["has_field"]["true_positives"] == 15
    assert evaluation["per_relation"]["has_field"]["candidate_edge_precision"] == 1.0
    assert evaluation["per_relation"]["has_field"]["recall"] == 1.0
    assert evaluation["per_relation"]["has_field"]["unsupported_edges"] == 0
    assert evaluation["provenance_completeness"] == 1.0
    assert evaluation["accepted_edge_count"] == 0
    assert evaluation["accepted_edge_precision"] is None
    assert manifest["summary"]["adjudicated_has_field_gold_edges"] == 15
    assert manifest["summary"]["exploratory_has_field_precision"] == 1.0
    assert manifest["summary"]["exploratory_has_field_recall"] == 1.0
    assert manifest["summary"]["accepted_has_field_edges"] == 0


def test_nevergone_ccjoystick_owner_methods_replay_is_reproducible() -> None:
    replay_dir = ROOT / (
        "docs/evidence/semantic-program-graph-v3/"
        "nevergone-ccjoystick-owner-methods-20261020"
    )
    manifest = json.loads((replay_dir / "replay-manifest.json").read_text(encoding="utf-8"))
    artifacts = {artifact["id"]: artifact for artifact in manifest["artifacts"]}
    paths = {
        artifact_id: (replay_dir / artifact["path"]).resolve()
        for artifact_id, artifact in artifacts.items()
    }
    for artifact_id, artifact in artifacts.items():
        raw = paths[artifact_id].read_bytes()
        assert len(raw) == artifact["bytes"]
        assert hashlib.sha256(raw).hexdigest() == artifact["sha256"]

    def merged_tsv(artifact_ids: list[str]) -> bytes:
        source_rows = [paths[artifact_id].read_text(encoding="utf-8").splitlines() for artifact_id in artifact_ids]
        assert all(rows[0] == source_rows[0][0] for rows in source_rows)
        return ("\n".join([source_rows[0][0], *(line for rows in source_rows for line in rows[1:])]) + "\n").encode()

    def merged_jsonl(artifact_ids: list[str]) -> bytes:
        return "".join(
            "\n".join(paths[artifact_id].read_text(encoding="utf-8").splitlines()) + "\n"
            for artifact_id in artifact_ids
        ).encode()

    assert merged_tsv([
        "init_parameter_loads", "update_touchpoint_loads", "raw_parameter_loads",
    ]) == paths["parameter_loads"].read_bytes()
    assert merged_tsv(["init_parameter_stores", "raw_parameter_stores"]) == paths["parameter_stores"].read_bytes()
    assert merged_jsonl([
        "init_memory_store_access", "update_touchpoint_memory_store_access", "raw_memory_store_access",
    ]) == paths["memory_store_access"].read_bytes()
    assert merged_tsv(["update_touchpoint_pcode_flow", "raw_pcode_flow"]) == paths["pcode_flow"].read_bytes()

    program_id = manifest["program_id"]
    entries = set(paths["function_entries"].read_text(encoding="utf-8").splitlines())
    expected_entries = {
        "002a5e08", "002a5ea0", "002a6048", "002a643c", "002a6570", "002a66c6",
    }
    assert entries == expected_entries
    prototypes = [
        json.loads(line) for line in paths["function_prototypes"].read_text(encoding="utf-8").splitlines()
    ]
    prototype_schema = _schema("ghidra-function-prototype-v1.schema.json")
    prototype_by_entry = {}
    for row in prototypes:
        prototype_schema.validate(row)
        assert row["program_sha256"] == manifest["program_sha256"]
        assert row["signature_source"] == "ANALYSIS"
        parameter = row["parameters"][0]
        assert parameter["index"] == 0
        assert parameter["type"]["kind"] == "pointer"
        assert parameter["type"]["target_name"] == "CCJoyStick"
        prototype_by_entry[row["resolved_entry"]] = row
    assert set(prototype_by_entry) == expected_entries | {"002a5f00", "002a6584"}
    plan_rows = list(csv.DictReader(paths["method_plan"].open(encoding="utf-8"), delimiter="\t"))
    assert {row["requested_entry"] for row in plan_rows} == set(prototype_by_entry)

    pcode_schema = _schema("ghidra-function-pcode-flow-v1.schema.json")
    raw_pcode = list(csv.DictReader(paths["raw_pcode_flow"].open(encoding="utf-8"), delimiter="\t"))
    for row in raw_pcode:
        pcode_schema.validate(row)
    pcode_by_key = {
        (row["function_entry"], row["op_address"], row["op_time"], row["opcode"]): row
        for row in raw_pcode
    }
    assert len(raw_pcode) == len(pcode_by_key) == 126
    assert {row["function_entry"] for row in raw_pcode} == expected_entries
    acquisition_schema = _schema("ghidra-pcode-flow-acquisition-v1.schema.json")
    acquisitions = [
        json.loads(line) for line in paths["raw_pcode_acquisition"].read_text(encoding="utf-8").splitlines()
    ]
    for row in acquisitions:
        acquisition_schema.validate(row)
        assert row["state"] == "complete"
        assert row["operation_count"] == sum(item["function_entry"] == row["function_entry"] for item in raw_pcode)
    assert {row["function_entry"] for row in acquisitions} == expected_entries
    callind_schema = _schema("ghidra-indirect-call-evidence-v4.schema.json")
    callind_rows = [
        json.loads(line) for line in paths["raw_callind_evidence"].read_text(encoding="utf-8").splitlines()
    ]
    for row in callind_rows:
        callind_schema.validate(row)

    load_schema = _schema("ghidra-parameter-load-field-v1.schema.json")
    raw_loads = list(csv.DictReader(paths["raw_parameter_loads"].open(encoding="utf-8"), delimiter="\t"))
    assert len(raw_loads) == 4
    for row in raw_loads:
        load_schema.validate(row)
        load = pcode_by_key[(row["function_entry"], row["load_address"], row["load_time"], "LOAD")]
        assert int(load["output"].rsplit(":", 1)[1]) == int(row["value_size"])
        assert row["value_token"].startswith("def:LOAD@")

    memory_schema = _schema("ghidra-memory-store-access-v1.schema.json")
    raw_memory_stores = [
        json.loads(line) for line in paths["raw_memory_store_access"].read_text(encoding="utf-8").splitlines()
    ]
    assert len(raw_memory_stores) == 13
    for row in raw_memory_stores:
        memory_schema.validate(row)
        store = pcode_by_key[(row["function_entry"], row["address"], str(row["time"]), "STORE")]
        store_inputs = store["inputs"].split(";")
        assert len(store_inputs) == 3
        assert store_inputs[1] == row["pointer_token"]
        assert int(store_inputs[2].rsplit(":", 1)[1]) == row["memory_width_bytes"]

    effects = build_function_effect_ir(
        program_id,
        parameter_store_tsv=paths["parameter_stores"],
        parameter_load_tsv=paths["parameter_loads"],
        memory_store_access_jsonl=paths["memory_store_access"],
        pcode_flow_tsv=paths["pcode_flow"],
    )
    effects_bytes = "".join(json.dumps(row, sort_keys=True) + "\n" for row in effects).encode()
    assert effects_bytes == paths["function_effect_ir"].read_bytes()
    assert len(effects) == 8

    layout_rows = build_type_layout_hypotheses(
        [paths["memory_store_access"]],
        [paths["type_layout_member_map"]],
        parameter_load_paths=[paths["parameter_loads"]],
        size_review_paths=[paths["size_review"]],
        field_type_review_paths=[paths["field_type_review"]],
        program_id=program_id,
        program_sha256=manifest["program_sha256"],
        language_id="ARM:LE:32:v8",
        pointer_width_bytes=4,
        addressable_unit_bytes=1,
        endianness="little",
    )
    layout_bytes = "".join(
        json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n" for row in layout_rows
    ).encode()
    assert layout_bytes == paths["type_layout_hypothesis"].read_bytes()
    layout_schema = _schema("type-layout-hypothesis-v1.schema.json")
    for row in layout_rows:
        layout_schema.validate(row)
    assert len(layout_rows[0]["fields"]) == 19
    assert layout_rows[0]["object_size"]["minimum_observed_bytes"] == 337
    assert layout_rows[0]["object_size"]["exact_size_bytes"] == 340

    effects, effects_sha = _read_jsonl(paths["function_effect_ir"])
    layouts, layout_sha = _read_jsonl(paths["type_layout_hypothesis"])
    member_maps, member_map_sha = _read_jsonl(paths["type_layout_member_map"])
    graph = build_semantic_program_graphs(
        effects,
        source_sha256=effects_sha,
        type_layout_rows=layouts,
        type_layout_sha256=layout_sha,
        type_layout_member_map_rows=member_maps,
        type_layout_member_map_sha256=member_map_sha,
    )[0]
    _schema("semantic-program-graph-v3.schema.json").validate(graph)
    graph_bytes = (json.dumps(graph, sort_keys=True) + "\n").encode()
    assert graph_bytes == paths["semantic_graph"].read_bytes()
    joins = [edge for edge in graph["edges"] if edge["relation"] == "has_field" and edge["to"].startswith("field:")]
    assert len(graph["nodes"]) == 168
    assert len(graph["edges"]) == 240
    assert len(joins) == 36

    query = query_graphs(
        [graph],
        source_sha256=hashlib.sha256(graph_bytes).hexdigest(),
        view="exploratory",
        kinds=["field"],
        function_entries=[row["function_entry"] for row in effects],
        relations=["has_field"],
    )[0]
    _schema("semantic-program-query-result-v1.schema.json").validate(query)
    assert (json.dumps(query, sort_keys=True) + "\n").encode() == paths["field_access_query"].read_bytes()
    assert len(query["nodes"]) == len(query["edges"]) == 36
    assert len(query["related_nodes"]) == 1

    [gold] = [
        json.loads(line) for line in paths["field_layout_gold"].read_text(encoding="utf-8").splitlines()
    ]
    _schema("semantic-program-graph-gold-v1.schema.json").validate(gold)
    type_node_id = f"type:{hashlib.sha256(json.dumps([program_id, layouts[0]['type_id']], separators=(',', ':')).encode()).hexdigest()}"
    layout_offsets = {field["offset_bytes"] for field in layouts[0]["fields"]}
    expected_gold_refs: dict[tuple[str, str], set[tuple[str, int, str]]] = {}
    edge_context: dict[tuple[str, str], tuple[str, int]] = {}
    for function in effects:
        entry = function["function_entry"]
        assert entry in prototype_by_entry
        for effect in function["effects"]:
            if effect["kind"] not in {"parameter_field_read", "parameter_field_write"} or effect["parameter_index"] != 0:
                continue
            offset = int(effect["field_offset"], 16)
            if offset not in layout_offsets:
                continue
            identity = [program_id, entry, 0, effect["field_offset"]]
            field_id = f"field:{hashlib.sha256(json.dumps(identity, separators=(',', ':')).encode()).hexdigest()}"
            edge_key = (type_node_id, field_id)
            edge_context[edge_key] = (entry, offset)
            expected_gold_refs.setdefault(edge_key, set()).add((
                effect["provenance"]["artifact_sha256"],
                effect["provenance"]["record_index"],
                effect["provenance"]["source_format"],
            ))
    gold_edges = {(edge["from"], edge["to"]): edge for edge in gold["edges"]}
    assert set(gold_edges) == set(expected_gold_refs)
    assert len(gold_edges) == 36
    assert set(gold["scope_node_ids"]) == {type_node_id, *(target for _, target in gold_edges)}
    assert "REVENGINSTR.TypeLayoutMemberMap/1" not in {
        ref["source_format"] for edge in gold["edges"] for ref in edge["evidence_refs"]
    }

    prototype_sha = artifacts["function_prototypes"]["sha256"]
    layout_artifact_sha = artifacts["type_layout_hypothesis"]["sha256"]
    prototype_indices = {row["resolved_entry"]: index for index, row in enumerate(prototypes, 1)}
    records_by_sha = {
        prototype_sha: prototypes,
        layout_artifact_sha: layouts,
        artifacts["parameter_loads"]["sha256"]: list(csv.DictReader(paths["parameter_loads"].open(encoding="utf-8"), delimiter="\t")),
        artifacts["parameter_stores"]["sha256"]: list(csv.DictReader(paths["parameter_stores"].open(encoding="utf-8"), delimiter="\t")),
        artifacts["memory_store_access"]["sha256"]: [
            json.loads(line) for line in paths["memory_store_access"].read_text(encoding="utf-8").splitlines()
        ],
    }
    source_formats = {
        "REVENGINSTR.GhidraFunctionPrototype/1",
        "REVENGINSTR.TypeLayoutHypothesis/1",
        "REVENGINSTR.GhidraParameterLoadField/1",
        "REVENGINSTR.GhidraParameterStoreField/1",
        "REVENGINSTR.GhidraMemoryStoreAccess/1",
    }
    for edge_key, edge in gold_edges.items():
        entry, offset = edge_context[edge_key]
        expected_refs = {
            (prototype_sha, prototype_indices[entry], "REVENGINSTR.GhidraFunctionPrototype/1"),
            (layout_artifact_sha, 1, "REVENGINSTR.TypeLayoutHypothesis/1"),
            *expected_gold_refs[edge_key],
        }
        actual_refs = {
            (ref["artifact_sha256"], ref["record_index"], ref["source_format"])
            for ref in edge["evidence_refs"]
        }
        assert actual_refs == expected_refs
        for source_sha, record_index, source_format in actual_refs:
            assert source_format in source_formats
            row = records_by_sha[source_sha][record_index - 1]
            assert row["format"] == source_format
            if source_format == "REVENGINSTR.GhidraFunctionPrototype/1":
                assert row["resolved_entry"] == entry
                assert row["parameters"][0]["type"]["target_name"] == "CCJoyStick"
            elif source_format == "REVENGINSTR.TypeLayoutHypothesis/1":
                assert row["type_id"] == layouts[0]["type_id"]
                assert offset in {field["offset_bytes"] for field in row["fields"]}
            else:
                assert row["function_entry"] == entry
                root_field = {
                    "REVENGINSTR.GhidraParameterLoadField/1": "base_parameter_index",
                    "REVENGINSTR.GhidraParameterStoreField/1": "destination_parameter_index",
                    "REVENGINSTR.GhidraMemoryStoreAccess/1": "root_parameter_index",
                }[source_format]
                assert int(row[root_field]) == 0
                raw_offset = row.get("field_offset", row.get("destination_offset"))
                if source_format == "REVENGINSTR.GhidraMemoryStoreAccess/1":
                    raw_offset = row["offset_bytes"]
                elif isinstance(raw_offset, str):
                    raw_offset = int(raw_offset, 16)
                assert raw_offset == offset

    evaluation = evaluate_semantic_program_graph(paths["semantic_graph"], paths["field_layout_gold"], view="exploratory")
    pinned_evaluation = json.loads(paths["field_layout_evaluation"].read_text(encoding="utf-8"))
    _schema("semantic-program-graph-evaluation-v1.schema.json").validate(evaluation)
    assert evaluation == pinned_evaluation
    assert evaluation["candidate_edge_count"] == 36
    assert evaluation["per_relation"]["has_field"]["true_positives"] == 36
    assert evaluation["per_relation"]["has_field"]["candidate_edge_precision"] == 1.0
    assert evaluation["per_relation"]["has_field"]["recall"] == 1.0
    assert evaluation["provenance_completeness"] == 1.0
    assert evaluation["accepted_edge_count"] == 0
    assert evaluation["accepted_edge_precision"] is None
    assert manifest["summary"]["joined_type_field_edges"] == 36
    assert manifest["summary"]["new_layout_offsets"] == ["0xe0", "0xe4", "0xe8", "0x12c", "0x138", "0x14c"]
    assert manifest["summary"]["accepted_has_field_edges"] == 0


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
