from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schemas/analysis-feedback-v1.schema.json").read_text(encoding="utf-8"))
FIXTURE = ROOT / "tests/fixtures/analysis-feedback/feedback.jsonl"


def test_analysis_feedback_fixture_covers_bounded_statuses() -> None:
    Draft202012Validator.check_schema(SCHEMA)
    validator = Draft202012Validator(SCHEMA)
    rows = [json.loads(line) for line in FIXTURE.read_text(encoding="utf-8").splitlines()]
    for row in rows:
        validator.validate(row)
    assert {row["status"] for row in rows} == {
        "confirmed", "rejected", "partially_correct", "ambiguous", "needs_more_evidence",
    }
    assert all(row["training_eligible"] is False for row in rows)


def test_analysis_feedback_requires_provenance_and_is_not_training_truth() -> None:
    validator = Draft202012Validator(SCHEMA)
    row = json.loads(FIXTURE.read_text(encoding="utf-8").splitlines()[0])
    invalid = json.loads(json.dumps(row))
    invalid["training_eligible"] = True
    with pytest.raises(ValidationError):
        validator.validate(invalid)

    invalid = json.loads(json.dumps(row))
    invalid["evidence"] = []
    with pytest.raises(ValidationError):
        validator.validate(invalid)

    invalid = json.loads(json.dumps(row))
    invalid["provenance_quality"] = "guaranteed"
    with pytest.raises(ValidationError):
        validator.validate(invalid)

    invalid = json.loads(json.dumps(row))
    invalid["reviewer"].update(kind="automated_tool", qualification="trained")
    with pytest.raises(ValidationError):
        validator.validate(invalid)
