from __future__ import annotations

import csv
import json
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/function-identities"


def _read_tsv(name: str) -> tuple[list[str], list[dict[str, str]]]:
    with (FIXTURES / name).open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t", strict=True)
        assert reader.fieldnames is not None
        return reader.fieldnames, list(reader)


def test_function_identity_fixtures_match_exporter_and_schemas() -> None:
    source = (ROOT / "ghidra/ExportGhidraFunctionIdentities.java").read_text(encoding="utf-8")
    plan_header, plan_rows = _read_tsv("plan.tsv")
    identity_header, identity_rows = _read_tsv("identities.tsv")
    plan_schema = json.loads(
        (ROOT / "schemas/ghidra-function-identities-plan-v1.schema.json").read_text(encoding="utf-8")
    )
    identity_schema = json.loads(
        (ROOT / "schemas/ghidra-function-identities-v1.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(plan_schema)
    Draft202012Validator.check_schema(identity_schema)

    assert "\\t".join(plan_header) in source
    assert "\\t".join(identity_header) in source
    assert plan_header == plan_schema["required"]
    assert identity_header == identity_schema["required"]
    assert identity_header == list(identity_schema["properties"])
    assert len(plan_rows) == len(identity_rows) == 2

    plan_validator = Draft202012Validator(plan_schema)
    identity_validator = Draft202012Validator(identity_schema)
    for row in plan_rows:
        plan_validator.validate(row)
    for row in identity_rows:
        identity_validator.validate(row)

    assert [(row["plan_id"], row["requested_entry"]) for row in plan_rows] == [
        (row["plan_id"], row["requested_entry"]) for row in identity_rows
    ]
    assert [row["resolution"] for row in plan_rows] == ["exact", "containing"]
    assert [row["resolved_entry"] for row in identity_rows] == ["00401000", "00401000"]
