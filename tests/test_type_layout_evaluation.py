from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.prototype_evaluation import evaluate_prototypes
from revenginstr.type_layout_evaluation import evaluate_type_layouts, main

ROOT = Path(__file__).resolve().parents[1]
PREDICTIONS = ROOT / "tests/fixtures/type-layout-hypothesis/synthetic.jsonl"
GOLD_FIXTURE = ROOT / "tests/fixtures/type-layout-gold/synthetic.jsonl"
PROTOTYPE_HYPOTHESES = ROOT / "tests/fixtures/function-prototype-hypothesis/synthetic.jsonl"
PROTOTYPE_GOLD = ROOT / "tests/fixtures/function-prototype-gold/synthetic.jsonl"


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def gold_row(*, audited: list[int] | None = None, field_offset: int = 32) -> dict:
    return {
        "format": "REVENGINSTR.TypeLayoutGold/1",
        "dataset_id": "synthetic-layouts",
        "split_id": "exact-fixtures-v1",
        "program_id": "synthetic-x86",
        "program_sha256": "a" * 64,
        "type_id": "opaque-type-1",
        "audited_field_offsets": audited or [32, 36],
        "fields": [{
            "offset_bytes": field_offset,
            "compatible_types": [{"kind": "data_pointer", "width_bytes": 4}],
            "evidence_refs": [{
                "artifact_sha256": "f" * 64,
                "record_index": 1,
                "source_format": "SyntheticIndependentLayout/1",
            }],
        }],
        "adjudication_status": "adjudicated",
    }


def prediction_rows() -> list[dict]:
    rows = [json.loads(line) for line in PREDICTIONS.read_text(encoding="utf-8").splitlines()]
    field = rows[0]["fields"][0]
    field["status"] = "review"
    negative = json.loads(json.dumps(field))
    negative["offset_bytes"] = 36
    negative["status"] = "candidate"
    outside = json.loads(json.dumps(field))
    outside["offset_bytes"] = 40
    rows[0]["fields"].extend([negative, outside])
    return rows


def test_evaluation_scores_only_explicitly_audited_offsets_and_reports_type_metrics(tmp_path: Path) -> None:
    predictions = tmp_path / "predictions.jsonl"
    gold = tmp_path / "gold.jsonl"
    write_jsonl(predictions, prediction_rows())
    write_jsonl(gold, [gold_row()])

    result = evaluate_type_layouts(predictions, gold)

    assert result["candidate_field_count"] == 2
    assert result["unscored_candidate_field_count"] == 1
    assert result["field_offset_true_positives"] == 1
    assert result["field_offset_precision"] == 0.5
    assert result["field_offset_recall"] == 1
    assert result["compatible_type_accuracy"] == 1
    assert result["compatible_type_review_coverage"] == 1
    assert result["reviewed_field_acceptance"] == 1
    assert result["high_confidence_reviewer_acceptance"] is None
    assert result["prototype_compatibility"] is None
    assert result["prototype_compatibility_status"] == "not_evaluated_no_prototype_evaluation_input"
    assert result["prototype_evaluation_sha256"] is None
    schema = json.loads((ROOT / "schemas/type-layout-evaluation-v1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(result)


def test_synthetic_exact_layout_gold_fixture_is_independent_and_scores_offsets() -> None:
    source = ROOT / "tests/fixtures/type-layout-gold/synthetic-source.jsonl"
    gold_rows = [json.loads(line) for line in GOLD_FIXTURE.read_text().splitlines()]
    gold_schema = json.loads((ROOT / "schemas/type-layout-gold-v1.schema.json").read_text())
    Draft202012Validator.check_schema(gold_schema)
    for row in gold_rows:
        Draft202012Validator(gold_schema).validate(row)
    assert gold_rows[0]["fields"][0]["evidence_refs"][0]["artifact_sha256"] == hashlib.sha256(
        source.read_bytes()
    ).hexdigest()

    result = evaluate_type_layouts(PREDICTIONS, GOLD_FIXTURE)

    assert result["field_offset_precision"] == 1
    assert result["field_offset_recall"] == 1
    assert result["field_offset_f1"] == 1
    assert result["compatible_type_accuracy"] is None


def test_layout_evaluation_accepts_matching_prototype_evaluation_report(tmp_path: Path) -> None:
    prototype_report = evaluate_prototypes(PROTOTYPE_HYPOTHESES, PROTOTYPE_GOLD)
    report_path = tmp_path / "prototype-evaluation.json"
    report_path.write_text(json.dumps(prototype_report) + "\n", encoding="utf-8")

    result = evaluate_type_layouts(
        PREDICTIONS, GOLD_FIXTURE, prototype_evaluation_path=report_path,
    )

    assert result["prototype_compatibility"] == 1
    assert result["prototype_compatibility_status"] == "evaluated"
    assert result["prototype_evaluation_sha256"] == hashlib.sha256(report_path.read_bytes()).hexdigest()


def test_layout_evaluation_rejects_prototype_report_from_another_split(tmp_path: Path) -> None:
    prototype_report = evaluate_prototypes(PROTOTYPE_HYPOTHESES, PROTOTYPE_GOLD)
    prototype_report["split_id"] = "other-split"
    report_path = tmp_path / "prototype-evaluation.json"
    report_path.write_text(json.dumps(prototype_report) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match="dataset/split does not match"):
        evaluate_type_layouts(
            PREDICTIONS, GOLD_FIXTURE, prototype_evaluation_path=report_path,
        )


def test_evaluation_rejects_positive_field_outside_audited_offsets(tmp_path: Path) -> None:
    predictions = tmp_path / "predictions.jsonl"
    gold = tmp_path / "gold.jsonl"
    write_jsonl(predictions, prediction_rows())
    write_jsonl(gold, [gold_row(audited=[36])])
    with pytest.raises(ValueError, match="outside audited_field_offsets"):
        evaluate_type_layouts(predictions, gold)


def test_evaluation_rejects_gold_that_cites_predictions(tmp_path: Path) -> None:
    predictions = tmp_path / "predictions.jsonl"
    gold = tmp_path / "gold.jsonl"
    write_jsonl(predictions, prediction_rows())
    row = gold_row()
    row["fields"][0]["evidence_refs"][0]["artifact_sha256"] = hashlib.sha256(
        predictions.read_bytes()
    ).hexdigest()
    write_jsonl(gold, [row])
    with pytest.raises(ValueError, match="cannot cite evaluated or gold output"):
        evaluate_type_layouts(predictions, gold)


def test_evaluation_cli_writes_report(tmp_path: Path, capsys) -> None:
    predictions = tmp_path / "predictions.jsonl"
    gold = tmp_path / "gold.jsonl"
    output = tmp_path / "nested" / "evaluation.json"
    write_jsonl(predictions, prediction_rows())
    write_jsonl(gold, [gold_row()])
    assert main([str(predictions), str(gold), "--output", str(output)]) == 0
    assert json.loads(output.read_text())["format"] == "REVENGINSTR.TypeLayoutEvaluation/1"
    assert "field-offset precision" in capsys.readouterr().out
