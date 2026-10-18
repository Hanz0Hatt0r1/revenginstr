from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.evidence.jsonl_export_parity import compare_exports, main


ROOT = Path(__file__).resolve().parents[1]


def test_jsonl_parity_ignores_object_key_order_and_reports_byte_difference(tmp_path: Path) -> None:
    left = tmp_path / "left.jsonl"
    right = tmp_path / "right.jsonl"
    left.write_text('{"a":1,"nested":{"x":true}}\n', encoding="utf-8")
    right.write_text('{"nested":{"x":true},"a":1}\n', encoding="utf-8")

    report = compare_exports(left, right)

    assert report["same_bytes"] is False
    assert report["same_records"] is True
    assert report["left_records"] == report["right_records"] == 1
    assert report["first_mismatch"] is None
    assert main([str(left), str(right)]) == 0


def test_jsonl_parity_reports_first_record_and_count_mismatches(tmp_path: Path) -> None:
    left = tmp_path / "left.jsonl"
    right = tmp_path / "right.jsonl"
    left.write_text('{"id":1}\n{"id":2}\n', encoding="utf-8")
    right.write_text('{"id":1}\n{"id":3}\n{"id":4}\n', encoding="utf-8")

    report = compare_exports(left, right)

    assert report["first_mismatch"] == {"kind": "record", "record_index": 2}
    assert report["left_records"] == 2
    assert report["right_records"] == 3
    assert "\"id\"" not in json.dumps(report)


def test_jsonl_parity_rejects_invalid_or_non_object_records(tmp_path: Path) -> None:
    left = tmp_path / "left.jsonl"
    right = tmp_path / "right.jsonl"
    right.write_text('{"id":1}\n', encoding="utf-8")

    for invalid in ("\n", "[]\n", '{"id":NaN}\n', '{"id":1,"id":2}\n'):
        left.write_text(invalid, encoding="utf-8")
        with pytest.raises(ValueError, match="invalid JSONL record"):
            compare_exports(left, right)


def test_jsonl_parity_cli_writes_schema_valid_report(tmp_path: Path) -> None:
    left = tmp_path / "left.jsonl"
    right = tmp_path / "right.jsonl"
    output = tmp_path / "reports" / "parity.json"
    left.write_text('{"id":1}\n', encoding="utf-8")
    right.write_text('{"id":2}\n', encoding="utf-8")

    assert main([str(left), str(right), "--output", str(output)]) == 1
    schema = json.loads((ROOT / "schemas/ghidra-jsonl-export-parity-v1.schema.json").read_text())
    report = json.loads(output.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(report)
    assert report["same_records"] is False


def test_jsonl_parity_accepts_two_empty_files(tmp_path: Path) -> None:
    left = tmp_path / "left.jsonl"
    right = tmp_path / "right.jsonl"
    left.write_text("", encoding="utf-8")
    right.write_text("", encoding="utf-8")

    report = compare_exports(left, right)

    assert report["same_records"] is True
    assert report["left_records"] == report["right_records"] == 0
