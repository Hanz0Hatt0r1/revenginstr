from __future__ import annotations

import csv
import json
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_SCHEMAS = {
    "ghidra-program-index/functions.tsv": "ghidra-program-index-functions-v1.schema.json",
    "ghidra-program-index/symbols.tsv": "ghidra-program-index-symbols-v1.schema.json",
    "ghidra-program-index/strings.tsv": "ghidra-program-index-strings-v1.schema.json",
    "ghidra-program-index/xrefs.tsv": "ghidra-program-index-xrefs-v1.schema.json",
    "ghidra-program-index/calls.tsv": "ghidra-program-index-calls-v1.schema.json",
    "ghidra-arm32-vtable-slots.tsv": "ghidra-arm32-itanium-vtable-slots-v1.schema.json",
}


def test_synthetic_ghidra_export_fixtures_match_v1_contracts() -> None:
    fixture_root = ROOT / "tests/fixtures"
    for fixture, schema_name in FIXTURE_SCHEMAS.items():
        schema = json.loads((ROOT / "schemas" / schema_name).read_text(encoding="utf-8"))
        validator = Draft202012Validator(schema)
        with (fixture_root / fixture).open(encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle, delimiter="\t")
            assert reader.fieldnames == schema["required"], fixture
            rows = list(reader)
        assert rows, fixture
        for row in rows:
            validator.validate(row)
