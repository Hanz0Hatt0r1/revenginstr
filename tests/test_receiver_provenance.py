from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

from revenginstr.receiver.provenance import FORMAT, validate_graph_references


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
