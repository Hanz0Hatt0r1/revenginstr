from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

from revenginstr.receiver.provenance import (
    FORMAT,
    CALLER_ARGUMENT_FORMAT,
    CALLER_PARAMETER_ROOT_FORMAT,
    PARAMETER_LOAD_FORMAT,
    PARAMETER_STORE_FORMAT,
    RECEIVER_TYPE_FORMAT,
    argument_store_main,
    argument_load_main,
    build_argument_load_graphs,
    build_argument_store_graphs,
    build_call_return_graphs,
    build_field_access_pair_graphs,
    build_parameter_load_return_graphs,
    build_recursive_argument_graph,
    build_caller_argument_graphs,
    build_parameter_store_graphs,
    build_receiver_graphs,
    caller_argument_main,
    call_return_main,
    field_access_pairs_main,
    main,
    parameter_store_main,
    parameter_load_return_main,
    recursive_argument_main,
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


def caller_parameter_root_row(**overrides: str) -> dict[str, str]:
    row = {
        "format": CALLER_PARAMETER_ROOT_FORMAT,
        "plan_id": "plan:sample",
        "callee_entry": "00401000",
        "parameter_index": "0",
        "caller_entry": "00402000",
        "caller_call_site": "00402010",
        "caller_parameter_index": "0",
        "argument_node_id": "0",
        "status": "direct_parameter_root",
    }
    row.update(overrides)
    return row


def test_recursive_argument_graph_follows_only_exact_formal_roots() -> None:
    arguments = [
        caller_argument_row(
            plan_id="plan-inner", callee_entry="00401000", parameter_index="0",
            caller_entry="00402000", caller_call_site="00402010",
        ),
        caller_argument_row(
            plan_id="plan-outer", callee_entry="00402000", parameter_index="0",
            caller_entry="00403000", caller_call_site="00403010",
        ),
        caller_argument_row(
            plan_id="plan-unused", callee_entry="00409900", parameter_index="1",
            caller_entry="00408800", caller_call_site="00408810",
        ),
    ]
    roots = [
        caller_parameter_root_row(
            plan_id="plan-inner", caller_parameter_index="0",
        ),
        caller_parameter_root_row(
            plan_id="plan-outer", callee_entry="00402000", caller_entry="00403000",
            caller_call_site="00403010", caller_parameter_index="1",
        ),
        caller_parameter_root_row(
            plan_id="plan-unused", callee_entry="00409900", parameter_index="1",
            caller_entry="00408800", caller_call_site="00408810", caller_parameter_index="2",
        ),
    ]

    graph = build_recursive_argument_graph(
        arguments, roots, target_entry="00401000", target_parameter_index=0,
        program_id="analysis:sample",
    )

    assert graph is not None
    Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))).validate(graph)
    assert len(graph["nodes"]) == 3
    assert len(graph["edges"]) == 2
    assert {edge["relation"] for edge in graph["edges"]} == {"argument_flow"}
    assert all(len(edge["provenance"]) == 2 for edge in graph["edges"])
    assert {
        item["source_format"]
        for edge in graph["edges"]
        for item in edge["provenance"]
    } == {CALLER_ARGUMENT_FORMAT, CALLER_PARAMETER_ROOT_FORMAT}
    with pytest.raises(ValueError, match="recursive argument depth exceeded"):
        build_recursive_argument_graph(
            arguments, roots, target_entry="00401000", target_parameter_index=0,
            program_id="analysis:sample", max_depth=1,
        )


def test_recursive_argument_graph_handles_cycles_and_fails_on_known_truncation() -> None:
    arguments = [
        caller_argument_row(
            plan_id="a-to-b", callee_entry="00401000", parameter_index="0",
            caller_entry="00402000", caller_call_site="00402010",
        ),
        caller_argument_row(
            plan_id="b-to-a", callee_entry="00402000", parameter_index="0",
            caller_entry="00401000", caller_call_site="00401010",
        ),
    ]
    roots = [
        caller_parameter_root_row(
            plan_id="a-to-b", caller_parameter_index="0",
        ),
        caller_parameter_root_row(
            plan_id="b-to-a", callee_entry="00402000", caller_entry="00401000",
            caller_call_site="00401010", caller_parameter_index="0",
        ),
    ]
    graph = build_recursive_argument_graph(
        arguments, roots, target_entry="00401000", target_parameter_index=0, program_id="p"
    )
    assert graph is not None and len(graph["edges"]) == 2


def test_recursive_argument_graph_requires_sidecars_to_match_root_rows() -> None:
    with pytest.raises(ValueError, match="no matching argument root"):
        build_recursive_argument_graph(
            [caller_argument_row()],
            [caller_parameter_root_row(caller_call_site="0040ffff")],
            target_entry="00401000", target_parameter_index=0, program_id="p",
        )


def test_recursive_argument_graph_caps_selected_edges() -> None:
    arguments = [
        caller_argument_row(
            plan_id="caller-b", parameter_index="0", caller_entry="00402000",
            caller_call_site="00402010",
        ),
        caller_argument_row(
            plan_id="caller-c", parameter_index="0", caller_entry="00403000",
            caller_call_site="00403010",
        ),
    ]
    roots = [
        caller_parameter_root_row(
            plan_id="caller-b", caller_entry="00402000", caller_call_site="00402010"
        ),
        caller_parameter_root_row(
            plan_id="caller-c", caller_entry="00403000", caller_call_site="00403010"
        ),
    ]

    with pytest.raises(ValueError, match="recursive argument edge budget exceeded"):
        build_recursive_argument_graph(
            arguments, roots, target_entry="00401000", target_parameter_index=0,
            program_id="p", max_edges=1,
        )


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


def parameter_load_row(**overrides: str) -> dict[str, str]:
    row = {
        "format": PARAMETER_LOAD_FORMAT,
        "function_entry": "00401000",
        "function_name": "FUN_00401000",
        "load_address": "00401020",
        "load_time": "7",
        "base_parameter_index": "0",
        "field_offset": "0x24",
        "address_pattern": "ptrsub",
        "value_size": "4",
        "value_token": "def:LOAD@00401020:7:4",
        "status": "parameter_field_load",
    }
    row.update(overrides)
    return row


def test_argument_load_join_uses_exact_callee_and_formal_parameter_keys() -> None:
    arguments = [
        caller_argument_row(parameter_index="0"),
        caller_argument_row(parameter_index="1", caller_call_site="00402020"),
        caller_argument_row(callee_entry="00409999", parameter_index="1", caller_call_site="00402030"),
    ]
    loads = [
        parameter_load_row(),
        parameter_load_row(function_entry="00409999", load_address="004099a0"),
        parameter_load_row(base_parameter_index="2", load_address="00401024"),
    ]

    graphs = build_argument_load_graphs(arguments, loads, program_id="analysis:sample")

    assert len(graphs) == 1
    graph = graphs[0]
    Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))).validate(graph)
    validate_graph_references(graph)
    assert {node["kind"] for node in graph["nodes"]} == {
        "call_argument", "parameter", "field_load"
    }
    edges = {(edge["from"], edge["to"], edge["relation"]) for edge in graph["edges"]}
    assert edges == {
        ("caller_argument", "callee_parameter", "argument_flow"),
        ("callee_parameter", "field_load", "field_load"),
    }
    assert graph["edges"][0]["provenance"][0]["source_format"] == CALLER_ARGUMENT_FORMAT
    load_edge = next(edge for edge in graph["edges"] if edge["relation"] == "field_load")
    assert load_edge["provenance"][0]["source_format"] == PARAMETER_LOAD_FORMAT


@pytest.mark.parametrize(
    ("rows", "message"),
    [
        ([parameter_load_row(format="consumer/1")], "unsupported format"),
        ([parameter_load_row(status="unknown")], "unsupported status"),
        ([parameter_load_row(base_parameter_index="x")], "invalid load key"),
        ([parameter_load_row(field_offset="0xGG")], "invalid load key"),
        ([parameter_load_row(), parameter_load_row()], "duplicate parameter load"),
    ],
)
def test_argument_load_join_fails_closed_on_invalid_loads(rows, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        build_argument_load_graphs(
            [caller_argument_row(parameter_index="0")], rows, program_id="p"
        )


def test_argument_load_join_fails_when_expansion_exceeds_budget() -> None:
    arguments = [
        caller_argument_row(parameter_index="0", caller_call_site="00402010"),
        caller_argument_row(parameter_index="0", caller_call_site="00402020"),
    ]
    loads = [
        parameter_load_row(),
        parameter_load_row(load_address="00401024", load_time="8", value_token="def:LOAD@00401024:8:4"),
    ]

    with pytest.raises(ValueError, match="argument-load graph budget exceeded"):
        build_argument_load_graphs(arguments, loads, program_id="p", max_graphs=2)


def test_argument_load_cli_writes_joined_graph(tmp_path: Path, capsys) -> None:
    arguments = tmp_path / "arguments.tsv"
    arguments.write_text(
        "format\trow_type\tplan_id\tcallee_entry\tparameter_index\tcaller_entry\t"
        "caller_call_site\tnode_id\tparent_node_id\tdepth\tedge_kind\n"
        f"{CALLER_ARGUMENT_FORMAT}\tnode\tplan:sample\t00401000\t0\t00402000\t"
        "00402010\t0\t-1\t0\troot\n",
        encoding="utf-8",
    )
    loads = tmp_path / "loads.tsv"
    loads.write_text(
        "format\tfunction_entry\tload_address\tload_time\tbase_parameter_index\t"
        "field_offset\tvalue_token\tstatus\n"
        f"{PARAMETER_LOAD_FORMAT}\t00401000\t00401020\t7\t0\t0x24\t"
        "def:LOAD@00401020:7:4\tparameter_field_load\n",
        encoding="utf-8",
    )
    output = tmp_path / "nested" / "joined.jsonl"

    assert argument_load_main([
        str(arguments), str(loads), "--program-id", "analysis:sample", "--output", str(output)
    ]) == 0
    graph = json.loads(output.read_text(encoding="utf-8"))
    assert "field_load" in {edge["relation"] for edge in graph["edges"]}
    assert "input parameter loads: 1" in capsys.readouterr().out


def test_field_access_pairs_require_exact_function_parameter_and_numeric_offset() -> None:
    stores = [
        parameter_store_row(),
        parameter_store_row(function_entry="00409999", store_address="004099a0"),
        parameter_store_row(destination_parameter_index="1", store_address="00401024"),
        parameter_store_row(destination_offset="0x20", store_address="00401028"),
    ]
    loads = [
        parameter_load_row(field_offset="0x024"),
        parameter_load_row(function_entry="00409998", load_address="004099b0"),
        parameter_load_row(base_parameter_index="2", load_address="00401024"),
        parameter_load_row(field_offset="0x22", load_address="00401028"),
    ]

    graphs = build_field_access_pair_graphs(stores, loads, program_id="analysis:sample")

    assert len(graphs) == 1
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    for graph in graphs:
        Draft202012Validator(schema).validate(graph)
        validate_graph_references(graph)
        assert {edge["relation"] for edge in graph["edges"]} == {
            "field_store", "data_flow", "field_load"
        }
        assert not any(
            edge["from"] == "store" and edge["to"] == "field_load"
            for edge in graph["edges"]
        )
        assert any(
            edge["provenance"][0]["source_format"] == PARAMETER_STORE_FORMAT
            for edge in graph["edges"] if edge["relation"] == "field_store"
        )
        assert any(
            edge["provenance"][0]["source_format"] == PARAMETER_LOAD_FORMAT
            for edge in graph["edges"] if edge["relation"] == "field_load"
        )


def test_field_access_pair_cli_writes_graphs(tmp_path: Path, capsys) -> None:
    stores = tmp_path / "stores.tsv"
    stores.write_text(
        "format\tfunction_entry\tstore_address\tstore_time\tdestination_parameter_index\t"
        "destination_offset\tsource_parameter_index\tstatus\n"
        f"{PARAMETER_STORE_FORMAT}\t00401000\t00401020\t7\t0\t0x24\t1\t"
        "parameter_to_parameter_field\n",
        encoding="utf-8",
    )
    loads = tmp_path / "loads.tsv"
    loads.write_text(
        "format\tfunction_entry\tload_address\tload_time\tbase_parameter_index\t"
        "field_offset\tvalue_token\tstatus\n"
        f"{PARAMETER_LOAD_FORMAT}\t00401000\t00401030\t8\t0\t0x24\t"
        "def:LOAD@00401030:8:4\tparameter_field_load\n",
        encoding="utf-8",
    )
    output = tmp_path / "nested" / "pairs.jsonl"

    assert field_access_pairs_main([
        str(stores), str(loads), "--program-id", "analysis:sample", "--output", str(output)
    ]) == 0
    graph = json.loads(output.read_text(encoding="utf-8"))
    assert {edge["relation"] for edge in graph["edges"]} == {
        "field_store", "data_flow", "field_load"
    }
    assert "compatible field access pairs: 1" in capsys.readouterr().out


def test_field_access_pair_budget_caps_cartesian_expansion() -> None:
    stores = [
        parameter_store_row(store_address="00401020"),
        parameter_store_row(store_address="00401024"),
    ]
    loads = [
        parameter_load_row(load_address="00401030"),
        parameter_load_row(load_address="00401034", load_time="8", value_token="def:LOAD@00401034:8:4"),
    ]

    with pytest.raises(ValueError, match="field access pair graph budget exceeded"):
        build_field_access_pair_graphs(stores, loads, program_id="p", max_graphs=2)


def pcode_flow_row(**overrides: str) -> dict[str, str]:
    row = {
        "function_entry": "00401000",
        "op_address": "00401020",
        "op_time": "7",
        "opcode": "LOAD",
        "output": "def:00401020:7:4",
        "inputs": "const:0x1:4;def:00401020:1:8",
        "callee_entry": "-",
        "callee_name": "-",
    }
    row.update(overrides)
    return row


def test_parameter_load_return_flow_traces_exact_pcode_def_use_path() -> None:
    loads = [parameter_load_row(
        load_address="00401020", load_time="7", value_token="def:LOAD@00401020:7:4"
    )]
    pcode = [
        pcode_flow_row(),
        pcode_flow_row(
            op_address="00401024", op_time="8", opcode="COPY",
            output="def:00401024:8:4", inputs="def:00401020:7:4",
        ),
        pcode_flow_row(
            op_address="00401030", op_time="9", opcode="RETURN",
            output="-", inputs="const:0x0:8;def:00401024:8:4",
        ),
    ]

    graphs = build_parameter_load_return_graphs(loads, pcode, program_id="analysis:sample")

    assert len(graphs) == 1
    graph = graphs[0]
    Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))).validate(graph)
    assert graph["edges"][0]["evidence_class"] == "derived_structural"
    assert graph["edges"][0]["relation"] == "return_flow"
    provenance = graph["edges"][0]["provenance"]
    assert provenance[0]["source_format"] == PARAMETER_LOAD_FORMAT
    assert [row["source_format"] for row in provenance[1:]] == [
        "REVENGINSTR.GhidraFunctionPcodeFlow/1",
        "REVENGINSTR.GhidraFunctionPcodeFlow/1",
        "REVENGINSTR.GhidraFunctionPcodeFlow/1",
    ]


def test_parameter_load_return_flow_omits_unreturned_values_and_rejects_mismatches() -> None:
    load = parameter_load_row(
        load_address="00401020", load_time="7", value_token="def:LOAD@00401020:7:4"
    )
    pcode = [
        pcode_flow_row(),
        pcode_flow_row(
            op_address="00401024", op_time="8", opcode="COPY",
            output="def:00401024:8:4", inputs="def:00401020:7:4",
        ),
    ]
    assert build_parameter_load_return_graphs([load], pcode, program_id="p") == []

    with pytest.raises(ValueError, match="no matching P-code LOAD definition"):
        build_parameter_load_return_graphs([load], pcode[1:], program_id="p")


@pytest.mark.parametrize(
    ("bridge_opcode", "bridge_inputs"),
    [
        ("CALL", "def:00401020:7:4"),
        ("INDIRECT", "const:0x1:4;def:00401020:7:4"),
    ],
)
def test_parameter_load_return_flow_does_not_overclaim_call_or_reference_dependencies(
    bridge_opcode: str, bridge_inputs: str
) -> None:
    load = parameter_load_row(
        load_address="00401020", load_time="7", value_token="def:LOAD@00401020:7:4"
    )
    pcode = [
        pcode_flow_row(),
        pcode_flow_row(
            op_address="00401024", op_time="8", opcode=bridge_opcode,
            output="def:00401024:8:4", inputs=bridge_inputs,
        ),
        pcode_flow_row(
            op_address="00401030", op_time="9", opcode="RETURN",
            output="-", inputs="def:00401024:8:4",
        ),
    ]

    assert build_parameter_load_return_graphs([load], pcode, program_id="p") == []


def test_parameter_load_return_flow_caps_multiple_return_graphs() -> None:
    load = parameter_load_row(
        load_address="00401020", load_time="7", value_token="def:LOAD@00401020:7:4"
    )
    pcode = [
        pcode_flow_row(),
        pcode_flow_row(
            op_address="00401030", op_time="9", opcode="RETURN",
            output="-", inputs="def:00401020:7:4",
        ),
        pcode_flow_row(
            op_address="00401034", op_time="10", opcode="RETURN",
            output="-", inputs="def:00401020:7:4",
        ),
    ]

    with pytest.raises(ValueError, match="load-return graph budget exceeded"):
        build_parameter_load_return_graphs([load], pcode, program_id="p", max_graphs=1)


def test_call_return_flow_traces_explicit_call_result_to_return() -> None:
    pcode = [
        pcode_flow_row(
            opcode="CALL", output="def:00401020:7:4", inputs="const:0x401100:4",
            callee_entry="00401100", callee_name="FUN_00401100",
        ),
        pcode_flow_row(
            op_address="00401024", op_time="8", opcode="COPY",
            output="def:00401024:8:4", inputs="def:00401020:7:4",
        ),
        pcode_flow_row(
            op_address="00401030", op_time="9", opcode="RETURN",
            output="-", inputs="const:0x0:8;def:00401024:8:4",
        ),
    ]

    graphs = build_call_return_graphs(pcode, program_id="analysis:sample")

    assert len(graphs) == 1
    graph = graphs[0]
    Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))).validate(graph)
    edge = graph["edges"][0]
    assert edge["relation"] == "return_flow"
    assert edge["evidence_class"] == "derived_structural"
    assert [json.loads(row["source_id"])[-1] for row in edge["provenance"]] == [
        "CALL", "COPY", "RETURN"
    ]


@pytest.mark.parametrize(
    ("bridge_opcode", "bridge_inputs", "expected_call_result", "origin_address"),
    [
        ("CALL", "def:00401020:7:4", True, "00401024"),
        ("CALLIND", "def:00401020:7:4", True, "00401024"),
        ("CALLOTHER", "def:00401020:7:4", False, ""),
        ("INDIRECT", "const:0x1:4;def:00401020:7:4", False, ""),
        ("INDIRECT", "def:00401020:7:4;const:0x1:4", True, "00401020"),
    ],
)
def test_call_return_flow_does_not_cross_call_or_reference_barriers(
    bridge_opcode: str, bridge_inputs: str, expected_call_result: bool, origin_address: str
) -> None:
    pcode = [
        pcode_flow_row(opcode="CALL", output="def:00401020:7:4"),
        pcode_flow_row(
            op_address="00401024", op_time="8", opcode=bridge_opcode,
            output="def:00401024:8:4", inputs=bridge_inputs,
        ),
        pcode_flow_row(
            op_address="00401030", op_time="9", opcode="RETURN",
            output="-", inputs="def:00401024:8:4",
        ),
    ]

    graphs = build_call_return_graphs(pcode, program_id="p")
    if expected_call_result:
        assert len(graphs) == 1
        assert json.loads(graphs[0]["edges"][0]["provenance"][0]["source_id"])[2] == origin_address
    else:
        assert graphs == []


def test_call_return_flow_ignores_void_calls_and_caps_returns() -> None:
    void_call = pcode_flow_row(opcode="CALL", output="-", inputs="const:0x401100:4")
    direct_call = pcode_flow_row(opcode="CALL", output="def:00401020:7:4")
    returns = [
        pcode_flow_row(
            op_address=f"004010{offset:02x}", op_time=str(time), opcode="RETURN",
            output="-", inputs="def:00401020:7:4",
        )
        for offset, time in ((0x30, 9), (0x34, 10))
    ]

    assert build_call_return_graphs([void_call], program_id="p") == []
    with pytest.raises(ValueError, match="call-return graph budget exceeded"):
        build_call_return_graphs([direct_call, *returns], program_id="p", max_graphs=1)


def test_call_return_cli_writes_flow_graph(tmp_path: Path, capsys) -> None:
    pcode = tmp_path / "function-pcode-flow.tsv"
    pcode.write_text(
        "function_entry\top_address\top_time\topcode\toutput\tinputs\tcallee_entry\tcallee_name\n"
        "00401000\t00401020\t7\tCALL\tdef:00401020:7:4\tconst:0x401100:4\t00401100\tFUN_00401100\n"
        "00401000\t00401030\t9\tRETURN\t-\tdef:00401020:7:4\t-\t-\n",
        encoding="utf-8",
    )
    output = tmp_path / "nested" / "call-return.jsonl"

    assert call_return_main([
        str(pcode), "--program-id", "analysis:sample", "--output", str(output)
    ]) == 0
    graph = json.loads(output.read_text(encoding="utf-8"))
    assert graph["edges"][0]["relation"] == "return_flow"
    assert "call-return graphs: 1" in capsys.readouterr().out


def test_parameter_load_return_cli_writes_flow_graph(tmp_path: Path, capsys) -> None:
    loads = tmp_path / "loads.tsv"
    loads.write_text(
        "format\tfunction_entry\tload_address\tload_time\tbase_parameter_index\t"
        "field_offset\tvalue_size\tvalue_token\tstatus\n"
        f"{PARAMETER_LOAD_FORMAT}\t00401000\t00401020\t7\t0\t0x24\t4\t"
        "def:LOAD@00401020:7:4\tparameter_field_load\n",
        encoding="utf-8",
    )
    pcode = tmp_path / "pcode.tsv"
    pcode.write_text(
        "function_entry\top_address\top_time\topcode\toutput\tinputs\tcallee_entry\tcallee_name\n"
        "00401000\t00401020\t7\tLOAD\tdef:00401020:7:4\tconst:0x1:4\t-\t-\n"
        "00401000\t00401030\t9\tRETURN\t-\tdef:00401020:7:4\t-\t-\n",
        encoding="utf-8",
    )
    output = tmp_path / "nested" / "flows.jsonl"

    assert parameter_load_return_main([
        str(loads), str(pcode), "--program-id", "analysis:sample", "--output", str(output)
    ]) == 0
    graph = json.loads(output.read_text(encoding="utf-8"))
    assert graph["edges"][0]["relation"] == "return_flow"
    assert "load-return graphs: 1" in capsys.readouterr().out


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


def test_argument_store_join_uses_exact_callee_and_formal_parameter_keys() -> None:
    argument_rows = [
        caller_argument_row(parameter_index="0"),
        caller_argument_row(parameter_index="1", caller_call_site="00402020"),
        caller_argument_row(parameter_index="2", caller_call_site="00402030"),
    ]
    store_rows = [
        parameter_store_row(),
        parameter_store_row(function_entry="00409999", store_address="004099a0"),
    ]

    graphs = build_argument_store_graphs(
        argument_rows, store_rows, program_id="analysis:sample"
    )

    assert len(graphs) == 2
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    for graph in graphs:
        Draft202012Validator(schema).validate(graph)
        validate_graph_references(graph)
        identity = json.loads(graph["graph_id"])
        argument_identity = json.loads(identity[1])
        parameter_index = argument_identity[2]
        edges = {(edge["from"], edge["to"], edge["relation"]) for edge in graph["edges"]}
        assert ("caller_argument", "callee_parameter", "argument_flow") in edges
        if parameter_index == 0:
            assert ("callee_parameter", "field_store", "field_store") in edges
        else:
            assert ("callee_parameter", "field_store", "data_flow") in edges
        assert any(
            edge["provenance"][0]["source_format"] == CALLER_ARGUMENT_FORMAT
            for edge in graph["edges"] if edge["relation"] == "argument_flow"
        )
        assert any(
            edge["provenance"][0]["source_format"] == PARAMETER_STORE_FORMAT
            for edge in graph["edges"] if edge["relation"] in {"field_store", "data_flow"}
        )


def test_argument_store_join_fails_when_join_expands_past_budget() -> None:
    arguments = [
        caller_argument_row(caller_call_site="00402010"),
        caller_argument_row(caller_call_site="00402020"),
    ]
    stores = [
        parameter_store_row(store_address="00401020"),
        parameter_store_row(store_address="00401024"),
    ]

    with pytest.raises(ValueError, match="argument-store graph budget exceeded"):
        build_argument_store_graphs(arguments, stores, program_id="p", max_graphs=2)


def test_argument_store_cli_writes_joined_graph(tmp_path: Path, capsys) -> None:
    arguments = tmp_path / "arguments.tsv"
    arguments.write_text(
        "format\trow_type\tplan_id\tcallee_entry\tparameter_index\tcaller_entry\t"
        "caller_call_site\tnode_id\tparent_node_id\tdepth\tedge_kind\n"
        f"{CALLER_ARGUMENT_FORMAT}\tnode\tplan\t00401000\t0\t00402000\t"
        "00402010\t0\t-1\t0\troot\n",
        encoding="utf-8",
    )
    stores = tmp_path / "stores.tsv"
    stores.write_text(
        "format\tfunction_entry\tstore_address\tstore_time\tdestination_parameter_index\t"
        "destination_offset\tsource_parameter_index\tstatus\n"
        f"{PARAMETER_STORE_FORMAT}\t00401000\t00401020\t7\t0\t0x24\t1\t"
        "parameter_to_parameter_field\n",
        encoding="utf-8",
    )
    output = tmp_path / "joined.jsonl"

    assert argument_store_main([
        str(arguments), str(stores), "--program-id", "analysis:sample", "--output", str(output)
    ]) == 0
    graph = json.loads(output.read_text(encoding="utf-8"))
    assert {edge["relation"] for edge in graph["edges"]} == {"argument_flow", "field_store", "data_flow"}
    assert "joined graphs: 1" in capsys.readouterr().out
