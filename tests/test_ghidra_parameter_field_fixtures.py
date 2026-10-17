from __future__ import annotations

import csv
import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
EXPORTER = ROOT / "ghidra/ExportGhidraParameterStoreField.java"
FIXTURES = ROOT / "tests/fixtures/parameter-field"


def _java_header(source: str, writer: str) -> list[str]:
    match = re.search(rf"{writer}\.write\((.*?)\);", source, re.DOTALL)
    assert match is not None
    literals = re.findall(r'"((?:\\.|[^"\\])*)"', match.group(1))
    return json.loads('"' + "".join(literals) + '"').split("\t")


def _read_tsv(path: Path) -> tuple[list[str], list[dict[str, str]]]:
    with path.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t", strict=True)
        assert reader.fieldnames is not None
        return reader.fieldnames, list(reader)


def test_parameter_field_fixtures_match_exported_headers_and_schemas() -> None:
    source = EXPORTER.read_text(encoding="utf-8")
    cases = (
        (
            "storeOut",
            "parameter-stores.tsv",
            "ghidra-parameter-store-field-v1.schema.json",
        ),
        (
            "loadOut",
            "parameter-loads.tsv",
            "ghidra-parameter-load-field-v1.schema.json",
        ),
    )

    for writer, fixture_name, schema_name in cases:
        header, rows = _read_tsv(FIXTURES / fixture_name)
        schema = json.loads((ROOT / "schemas" / schema_name).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)

        assert header == _java_header(source, writer)
        assert header == schema["required"]
        assert header == list(schema["properties"])
        assert len(rows) == 2
        validator = Draft202012Validator(schema)
        for row in rows:
            validator.validate(row)
