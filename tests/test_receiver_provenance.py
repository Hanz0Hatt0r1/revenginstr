from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

from revenginstr.receiver.provenance import (
    FORMAT,
    CALLER_ARGUMENT_FORMAT,
    PARAMETER_STORE_FORMAT,
    RECEIVER_TYPE_FORMAT,
    build_caller_argument_graphs,
    build_parameter_store_graphs,
    build_receiver_graphs,
    caller_argument_main,
    main,
    parameter_store_main,
    validate_graph_references,
)


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "receiver-provenance-graph-v1.schema.json"


@pytest.fixture
def graph() -> dict:
    return {
        "format": FORMAT,
        "graph_id": "synthetic:receiver-flow",
        "nodes": [
            {"id": "arg0", "kind": "parameter"},
            {"id": "store0", "kind": "field_store"},
            {"id": "load0", "kind": "field_load"},
            {"id": "call0", "kind": "indirect_call"},
            {"id": "receiver0", "kind": "receiver"},
        ],
        "edges": [
            {
                "id": "e0",
                "from": "arg0",
                "to": "store0",
                "relation": "field_store",
                "evidence_class": "exact_static",
                "provenance": [{
                    "source_format": "REVENGINSTR.GhidraParameterStoreField/1",
                    "source_id": "sample:1000#store0",
                }],
            },
            {
                "id": "e1",
                "from": "store0",
                "to": "load0",
                "relation": "field_load",
                "evidence_class": "derived_structural",
                "provenance": [{
                    "source_format": "REVENGINSTR.GhidraFunctionPcodeFlow/1",
                    "source_id": "sample:1000#load0",
                }],
            },
            {
                "id": "e2",
                "from": "load0",
                "to": "receiver0",
                "relation": "receiver_at_call",
                "evidence_class": "derived_structural",
                "provenance": [{
                    "source_format": "REVENGINSTR.GhidraIndirectReceiverType/1",
                    "source_id": "sample:1000#call0",
                }],
            },
            {
                "id": "e3",
                "from": "receiver0",
                "to": "call0",
                "relation": "receiver_at_call",
                "evidence_class": "exact_static",
                "provenance": [{
                    "source_format": "REVENGINSTR.GhidraIndirectCallEvidence/1",
                    "source_id": "sample:1000#call0",
                }],
            },
        ],
    }


def test_graph_schema_and_references_accept_synthetic_flow(graph: dict) -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(graph)
    validate_graph_references(graph)


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda graph: graph["nodes"].append(dict(graph["nodes"][0])), "duplicate receiver provenance node id"),
        (lambda graph: graph["edges"].append(dict(graph["edges"][0])), "duplicate receiver provenance edge id"),
        (lambda graph: graph["edges"][0].update(to="missing"), "has a dangling endpoint"),
    ],
)
def test_graph_reference_integrity_fails_closed(graph: dict, mutate, message: str) -> None:
    mutate(graph)
    with pytest.raises(ValueError, match=message):
        validate_graph_references(graph)


@pytest.mark.parametrize("field", ["evidence_class", "provenance"])
def test_graph_schema_requires_edge_evidence_and_provenance(graph: dict, field: str) -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    del graph["edges"][0][field]
    with pytest.raises(ValidationError):
        validator.validate(graph)


def test_graph_schema_rejects_empty_node_list(graph: dict) -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    graph["nodes"] = []
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(graph)


def receiver_row(call_index: str, receiver_present: str = "1") -> dict[str, str]:
    return {
        "format": RECEIVER_TYPE_FORMAT,
        "source_id": "sample:1000",
        "call_index": call_index,
        "receiver_present": receiver_present,
    }


def test_builder_emits_only_observed_receiver_call_edges() -> None:
    graphs, missing = build_receiver_graphs([
        receiver_row("2", "0"),
        receiver_row("1"),
    ])

    assert missing == 1
    assert [graph["graph_id"] for graph in graphs] == ["sample:1000#1"]
    edge = graphs[0]["edges"][0]
    assert edge["evidence_class"] == "exact_static"
    assert edge["provenance"] == [{
        "source_format": RECEIVER_TYPE_FORMAT,
        "source_id": "sample:1000#1",
    }]
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(graphs[0])


@pytest.mark.parametrize(
    ("rows", "message"),
    [
        ([{**receiver_row("0"), "format": "consumer/1"}], "unsupported format"),
        ([receiver_row("0", "2")], "invalid receiver_present"),
        ([receiver_row("0"), receiver_row("0")], "duplicate receiver row"),
        ([receiver_row("x")], "invalid receiver key"),
        ([receiver_row("٠")], "invalid receiver key"),
    ],
)
def test_builder_fails_closed_on_invalid_rows(rows: list[dict[str, str]], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        build_receiver_graphs(rows)


def test_builder_cli_writes_graph_jsonl_and_reports_omissions(tmp_path: Path, capsys) -> None:
    source = tmp_path / "receiver-types.tsv"
    source.write_text(
        "format\tsource_id\tcall_index\treceiver_present\n"
        f"{RECEIVER_TYPE_FORMAT}\tsample:1000\t0\t1\n"
        f"{RECEIVER_TYPE_FORMAT}\tsample:1000\t1\t0\n",
        encoding="utf-8",
    )
    output = tmp_path / "nested" / "graphs.jsonl"

    assert main([str(source), "--output", str(output)]) == 0
    assert json.loads(output.read_text(encoding="utf-8"))["graph_id"] == "sample:1000#0"
    assert "calls without receiver: 1" in capsys.readouterr().out


def caller_argument_row(**overrides: str) -> dict[str, str]:
    row = {
        "format": CALLER_ARGUMENT_FORMAT,
        "row_type": "node",
        "plan_id": "plan:sample",
        "callee_entry": "00401000",
        "parameter_index": "1",
        "caller_entry": "00402000",
        "caller_call_site": "00402010",
        "node_id": "0",
        "parent_node_id": "-1",
        "depth": "0",
        "edge_kind": "root",
    }
    row.update(overrides)
    return row


def test_builder_projects_bounded_root_to_formal_parameter() -> None:
    root = caller_argument_row()
    child = caller_argument_row(node_id="1", parent_node_id="0", depth="1", edge_kind="base")
    summary = caller_argument_row(row_type="summary")

    graphs, skipped = build_caller_argument_graphs([child, summary, root])

    assert skipped == 2
    assert len(graphs) == 1
    graph = graphs[0]
    assert [node["kind"] for node in graph["nodes"]] == ["call_argument", "parameter"]
    edge = graph["edges"][0]
    assert (edge["from"], edge["to"], edge["relation"]) == (
        "caller_argument", "callee_parameter", "argument_flow"
    )
    assert edge["evidence_class"] == "exact_static"
    assert edge["provenance"][0]["source_format"] == CALLER_ARGUMENT_FORMAT
    Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))).validate(graph)


@pytest.mark.parametrize("opcode", ["CALL", "CALLIND"])
def test_caller_argument_graph_records_generic_call_result(opcode: str) -> None:
    graphs, _skipped = build_caller_argument_graphs([
        caller_argument_row(defining_opcode=opcode)
    ])

    graph = graphs[0]
    assert {node["kind"] for node in graph["nodes"]} == {"call_argument", "parameter", "return"}
    return_edge = next(edge for edge in graph["edges"] if edge["relation"] == "return_flow")
    assert (return_edge["from"], return_edge["to"]) == ("call_result", "caller_argument")
    assert return_edge["provenance"] == graph["edges"][0]["provenance"]
    Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))).validate(graph)


@pytest.mark.parametrize(
    ("rows", "kwargs", "message"),
    [
        ([caller_argument_row(format="consumer/1")], {}, "unsupported format"),
        ([caller_argument_row(row_type="other")], {}, "invalid row_type"),
        ([caller_argument_row(parameter_index="x")], {}, "invalid root key"),
        ([caller_argument_row(parent_node_id="0")], {}, "invalid root key"),
        ([caller_argument_row(), caller_argument_row()], {}, "duplicate caller argument root"),
        ([caller_argument_row(), caller_argument_row(caller_call_site="00402020")], {"max_graphs": 1}, "budget exceeded"),
        ([], {"max_graphs": 0}, "max_graphs must be positive"),
    ],
)
def test_caller_argument_builder_fails_closed(rows, kwargs, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        build_caller_argument_graphs(rows, **kwargs)


def test_caller_argument_cli_writes_graph_jsonl_and_reports_skips(tmp_path: Path, capsys) -> None:
    source = tmp_path / "caller-argument-subtree.tsv"
    source.write_text(
        "format\trow_type\tplan_id\tcallee_entry\tparameter_index\tcaller_entry\t"
        "caller_call_site\tnode_id\tparent_node_id\tdepth\tedge_kind\n"
        f"{CALLER_ARGUMENT_FORMAT}\tnode\tplan:sample\t00401000\t1\t00402000\t"
        "00402010\t0\t-1\t0\troot\n"
        f"{CALLER_ARGUMENT_FORMAT}\tnode\tplan:sample\t00401000\t1\t00402000\t"
        "00402010\t1\t0\t1\tbase\n",
        encoding="utf-8",
    )
    output = tmp_path / "argument-flow.jsonl"

    assert caller_argument_main([
        str(source), "--output", str(output), "--max-graphs", "1"
    ]) == 0
    assert len(output.read_text(encoding="utf-8").splitlines()) == 1
    assert "subtree/summary rows skipped: 1" in capsys.readouterr().out


def parameter_store_row(**overrides: str) -> dict[str, str]:
    row = {
        "format": PARAMETER_STORE_FORMAT,
        "function_entry": "00401000",
        "function_name": "FUN_00401000",
        "store_address": "00401020",
        "store_time": "7",
        "destination_parameter_index": "0",
        "destination_offset": "0x24",
        "destination_pattern": "ptrsub",
        "source_parameter_index": "1",
        "value_size": "4",
        "status": "parameter_to_parameter_field",
    }
    row.update(overrides)
    return row


def test_builder_projects_destination_and_stored_value_edges() -> None:
    graphs = build_parameter_store_graphs(
        [parameter_store_row()], program_id="analysis:sample"
    )

    assert len(graphs) == 1
    graph = graphs[0]
    assert [node["id"] for node in graph["nodes"]] == [
        "parameter:0", "parameter:1", "store"
    ]
    assert [(edge["from"], edge["relation"]) for edge in graph["edges"]] == [
        ("parameter:0", "field_store"),
        ("parameter:1", "data_flow"),
    ]
    assert graph["edges"][0]["provenance"] == graph["edges"][1]["provenance"]
    assert graph["edges"][0]["provenance"][0]["source_format"] == PARAMETER_STORE_FORMAT
    Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))).validate(graph)


def test_parameter_store_builder_coalesces_same_parameter_node() -> None:
    graphs = build_parameter_store_graphs(
        [parameter_store_row(source_parameter_index="0")], program_id="analysis:sample"
    )
    assert [node["id"] for node in graphs[0]["nodes"]] == ["parameter:0", "store"]
    assert len(graphs[0]["edges"]) == 2


@pytest.mark.parametrize(
    ("rows", "kwargs", "message"),
    [
        ([parameter_store_row(format="consumer/1")], {"program_id": "p"}, "unsupported format"),
        ([parameter_store_row(status="unknown")], {"program_id": "p"}, "unsupported status"),
        ([parameter_store_row(destination_parameter_index="x")], {"program_id": "p"}, "invalid store key"),
        ([parameter_store_row(destination_offset="0xGG")], {"program_id": "p"}, "invalid store key"),
        ([parameter_store_row(), parameter_store_row(destination_parameter_index="00", source_parameter_index="01")], {"program_id": "p"}, "duplicate parameter store"),
        ([parameter_store_row()], {"program_id": "p", "max_graphs": 0}, "max_graphs must be positive"),
        ([parameter_store_row(), parameter_store_row(store_address="00401024")], {"program_id": "p", "max_graphs": 1}, "budget exceeded"),
    ],
)
def test_parameter_store_builder_fails_closed(rows, kwargs, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        build_parameter_store_graphs(rows, **kwargs)


def test_parameter_store_cli_writes_graph_jsonl(tmp_path: Path, capsys) -> None:
    source = tmp_path / "parameter-stores.tsv"
    source.write_text(
        "format\tfunction_entry\tstore_address\tstore_time\tdestination_parameter_index\t"
        "destination_offset\tsource_parameter_index\tstatus\n"
        f"{PARAMETER_STORE_FORMAT}\t00401000\t00401020\t7\t0\t0x24\t1\t"
        "parameter_to_parameter_field\n",
        encoding="utf-8",
    )
    output = tmp_path / "store-graphs.jsonl"

    assert parameter_store_main([
        str(source), "--program-id", "analysis:sample", "--output", str(output)
    ]) == 0
    graph = json.loads(output.read_text(encoding="utf-8"))
    assert graph["format"] == FORMAT
    assert "analysis:sample" in graph["graph_id"]
    assert "store graphs: 1" in capsys.readouterr().out
