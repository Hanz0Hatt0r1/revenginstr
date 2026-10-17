from __future__ import annotations

import base64
import csv
import json
import re
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]


def test_synthetic_defined_string_fixture_matches_exporter_and_schema() -> None:
    source = (ROOT / "ghidra/ExportGhidraPcodeDefinedStrings.java").read_text(encoding="utf-8")
    match = re.search(r"out\.write\((.*?)\);", source, re.DOTALL)
    assert match is not None
    literal = re.search(r'"((?:\\.|[^"\\])*)"', match.group(1))
    assert literal is not None
    exporter_header = json.loads('"' + literal.group(1) + '"').split("\t")

    fixture = ROOT / "tests/fixtures/defined-strings/defined-strings.tsv"
    with fixture.open(encoding="utf-8", newline="") as stream:
        reader = csv.DictReader(stream, delimiter="\t", strict=True)
        assert reader.fieldnames is not None
        rows = list(reader)

    schema = json.loads(
        (ROOT / "schemas/ghidra-pcode-defined-strings-v1.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    assert reader.fieldnames == exporter_header == schema["required"]
    assert exporter_header == list(schema["properties"])
    assert len(rows) == 2

    validator = Draft202012Validator(schema)
    decoded: list[str] = []
    for row in rows:
        validator.validate(row)
        raw = base64.b64decode(row["utf8_base64"], validate=True)
        text = raw.decode("utf-8")
        assert base64.b64encode(raw).decode("ascii") == row["utf8_base64"]
        assert len(text.encode("utf-16-le")) // 2 == int(row["length"])
        decoded.append(text)

    assert decoded == ["hello", "A😀B"]
