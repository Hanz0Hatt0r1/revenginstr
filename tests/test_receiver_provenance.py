from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

from revenginstr.receiver.provenance import (
    FORMAT,
    RECEIVER_TYPE_FORMAT,
    build_receiver_graphs,
    main,
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
