from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "receiver-candidate-evidence-v1.schema.json"
DIMENSIONS = (
    "exact_vtable_witness",
    "constructor_factory_witness",
    "field_layout_compatibility",
    "slot_compatibility",
    "caller_provenance",
    "callgraph_consistency",
    "runtime_witness",
)


def evidence_vector() -> dict:
    return {
        "format": "REVENGINSTR.ReceiverCandidateEvidence/1",
        "source_id": "sample:1000",
        "source_entry": "1000",
        "call_index": 2,
        "call_address": "1010",
        "candidate_id": "consumer-candidate-0",
        "dimensions": {
            name: {"status": "unknown", "evidence_class": None, "provenance": []}
            for name in DIMENSIONS
        },
    }


def test_candidate_evidence_vector_keeps_dimensions_and_states_explicit() -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    vector = evidence_vector()
    vector["dimensions"]["exact_vtable_witness"] = {
        "status": "supported",
        "evidence_class": "exact_static",
        "provenance": [{
            "source_format": "REVENGINSTR.GhidraArm32ItaniumVtableSlots/1",
            "source_id": "analysis-hash:slot-row-4",
        }],
    }
    vector["dimensions"]["slot_compatibility"] = {
        "status": "contradicted",
        "evidence_class": "derived_structural",
        "provenance": [{
            "source_format": "REVENGINSTR.GhidraArm32ItaniumVtableSlots/1",
            "source_id": "analysis-hash:slot-row-4",
        }],
    }
    validator.validate(vector)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda value: value["dimensions"]["exact_vtable_witness"].update(status="supported"),
        lambda value: value["dimensions"]["runtime_witness"].update(
            provenance=[{"source_format": "consumer.runtime/1", "source_id": "event-1"}]
        ),
        lambda value: value["dimensions"].pop("callgraph_consistency"),
        lambda value: value.update(aggregate_score=0.99),
    ],
)
def test_candidate_evidence_schema_rejects_ambiguous_or_aggregate_rows(mutate) -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    value = deepcopy(evidence_vector())
    mutate(value)
    with pytest.raises(ValidationError):
        validator.validate(value)
