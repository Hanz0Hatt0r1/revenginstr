from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.semantic_roles import ROLES, evaluate_semantic_roles, main


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/semantic-role"


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def test_role_taxonomy_and_synthetic_rows_match_schemas() -> None:
    contracts = (
        ("semantic-role-label-v1.schema.json", FIXTURES / "labels.jsonl"),
        ("semantic-role-prediction-v1.schema.json", FIXTURES / "predictions.jsonl"),
    )
    for schema_name, fixture in contracts:
        schema = json.loads((ROOT / "schemas" / schema_name).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        validator = Draft202012Validator(schema)
        for row in _read_jsonl(fixture):
            validator.validate(row)
        assert schema["properties"]["roles"]["items"]["enum"] == list(ROLES)
    evaluation_schema = json.loads(
        (ROOT / "schemas/semantic-role-evaluation-v1.schema.json").read_text(encoding="utf-8")
    )
    assert evaluation_schema["properties"]["per_role"]["propertyNames"]["enum"] == list(ROLES)


def test_semantic_role_evaluation_reports_aggregate_multilabel_metrics() -> None:
    report = evaluate_semantic_roles(
        FIXTURES / "labels.jsonl",
        FIXTURES / "predictions.jsonl",
        training_families_path=FIXTURES / "training-families.jsonl",
    )
    schema = json.loads(
        (ROOT / "schemas/semantic-role-evaluation-v1.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(report)

    assert report["rows"] == 4
    assert report["family_count"] == 4
    assert report["family_disjointness"] == "verified"
    assert report["macro_f1_observed_roles"] == 6
    assert report["macro_f1_observed"] == pytest.approx(0.5)
    assert report["micro_f1"] == pytest.approx(2 / 3)
    assert report["exact_match_accuracy"] == pytest.approx(0.5)
    assert report["per_role"]["utility_container_math"]["false_negative"] == 1
    assert report["per_role"]["input_handler"]["false_positive"] == 1
    serialized = json.dumps(report)
    assert all(f"function-{letter}" not in serialized for letter in "abcd")
    assert "family-00000000000000000001" not in serialized


def test_semantic_role_evaluation_marks_unchecked_and_rejects_family_overlap(tmp_path: Path) -> None:
    unchecked = evaluate_semantic_roles(FIXTURES / "labels.jsonl", FIXTURES / "predictions.jsonl")
    assert unchecked["family_disjointness"] == "not_checked"
    assert unchecked["training_family_artifact_sha256"] is None

    overlap = tmp_path / "training-families.jsonl"
    row = _read_jsonl(FIXTURES / "training-families.jsonl")[0]
    row["id"] = "function-a"
    _write_jsonl(overlap, [row])
    with pytest.raises(ValueError, match="function ids overlap"):
        evaluate_semantic_roles(
            FIXTURES / "labels.jsonl",
            FIXTURES / "predictions.jsonl",
            training_families_path=overlap,
        )

    row["id"] = "training-function"
    row["family_id"] = "family-00000000000000000001"
    _write_jsonl(overlap, [row])
    with pytest.raises(ValueError, match="family sets overlap"):
        evaluate_semantic_roles(
            FIXTURES / "labels.jsonl",
            FIXTURES / "predictions.jsonl",
            training_families_path=overlap,
        )


def test_semantic_role_evaluation_fails_closed_on_unpaired_or_unreviewed_rows(tmp_path: Path) -> None:
    labels = _read_jsonl(FIXTURES / "labels.jsonl")
    predictions = _read_jsonl(FIXTURES / "predictions.jsonl")
    short_predictions = tmp_path / "short-predictions.jsonl"
    _write_jsonl(short_predictions, predictions[:-1])
    with pytest.raises(ValueError, match="ids do not match exactly"):
        evaluate_semantic_roles(FIXTURES / "labels.jsonl", short_predictions)

    predictions[0]["family_id"] = "family-00000000000000000005"
    mismatched_family = tmp_path / "mismatched-family.jsonl"
    _write_jsonl(mismatched_family, predictions)
    with pytest.raises(ValueError, match="family ids differ"):
        evaluate_semantic_roles(FIXTURES / "labels.jsonl", mismatched_family)

    labels[0]["adjudication_status"] = "provisional"
    provisional = tmp_path / "provisional-labels.jsonl"
    _write_jsonl(provisional, labels)
    with pytest.raises(ValueError, match="not adjudicated"):
        evaluate_semantic_roles(provisional, FIXTURES / "predictions.jsonl")


def test_semantic_role_evaluation_cli_writes_json_report(tmp_path: Path, capsys) -> None:
    output = tmp_path / "nested" / "evaluation.json"
    assert main([
        str(FIXTURES / "labels.jsonl"),
        str(FIXTURES / "predictions.jsonl"),
        "--output", str(output),
    ]) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    assert report["family_disjointness"] == "not_checked"
    assert "micro F1:" in capsys.readouterr().out
