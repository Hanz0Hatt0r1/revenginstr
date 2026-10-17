from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

from revenginstr.evidence.export_parity import compare_exports, main


ROOT = Path(__file__).resolve().parents[1]


def test_parity_accepts_identical_tsv_records(tmp_path: Path) -> None:
    left = tmp_path / "left.tsv"
    right = tmp_path / "right.tsv"
    content = "entry\tvalue\n0010\talpha\n0020\tbeta\n"
    left.write_text(content, encoding="utf-8")
    right.write_text(content, encoding="utf-8")

    report = compare_exports(left, right)

    assert report["same_bytes"] is True
    assert report["same_records"] is True
    assert report["left_rows"] == report["right_rows"] == 2
    assert report["first_mismatch"] is None


def test_parity_compares_decoded_rows_and_reports_first_difference(tmp_path: Path) -> None:
    left = tmp_path / "left.tsv"
    right = tmp_path / "right.tsv"
    left.write_bytes(b"entry\tvalue\r\n0010\talpha\r\n0020\tbeta\r\n")
    right.write_text("entry\tvalue\n0010\tchanged\n0020\tbeta\n", encoding="utf-8")

    report = compare_exports(left, right)

    assert report["same_bytes"] is False
    assert report["same_records"] is False
    assert report["first_mismatch"] == {"kind": "row", "record_index": 1}
    assert "alpha" not in json.dumps(report)


def test_parity_reports_header_and_row_count_mismatches(tmp_path: Path) -> None:
    left = tmp_path / "left.tsv"
    right = tmp_path / "right.tsv"
    left.write_text("entry\tvalue\n0010\talpha\n", encoding="utf-8")
    right.write_text("entry\tother\n0010\talpha\n0020\tbeta\n", encoding="utf-8")

    report = compare_exports(left, right)

    assert report["first_mismatch"] == {"kind": "header", "record_index": 0}
    assert report["left_rows"] == 1
    assert report["right_rows"] == 2


def test_parity_cli_writes_schema_valid_report_and_fails_on_mismatch(tmp_path: Path) -> None:
    left = tmp_path / "left.tsv"
    right = tmp_path / "right.tsv"
    output = tmp_path / "reports" / "parity.json"
    left.write_text("entry\tvalue\n0010\talpha\n", encoding="utf-8")
    right.write_text("entry\tvalue\n0010\tbeta\n", encoding="utf-8")

    assert main([str(left), str(right), "--output", str(output)]) == 1
    schema = json.loads((ROOT / "schemas/ghidra-export-parity-v1.schema.json").read_text())
    report = json.loads(output.read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(report)
    assert report["same_records"] is False


def test_parity_requires_a_header(tmp_path: Path) -> None:
    left = tmp_path / "left.tsv"
    right = tmp_path / "right.tsv"
    left.write_text("", encoding="utf-8")
    right.write_text("entry\n", encoding="utf-8")

    assert main([str(left), str(right)]) == 2
