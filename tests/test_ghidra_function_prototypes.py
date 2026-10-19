from __future__ import annotations

import csv
import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/ghidra-function-prototypes"


def test_ghidra_prototype_export_fixture_matches_schema_and_exporter() -> None:
    schema = json.loads((ROOT / "schemas/ghidra-function-prototype-v1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    records = [json.loads(line) for line in (FIXTURES / "prototypes.jsonl").read_text().splitlines()]
    validator = Draft202012Validator(schema)
    for record in records:
        validator.validate(record)
        assert record["parameter_count"] == len(record["parameters"])

    with (FIXTURES / "plan.tsv").open(encoding="utf-8", newline="") as handle:
        plan = list(csv.DictReader(handle, delimiter="\t", strict=True))
    assert [(row["plan_id"], row["requested_entry"]) for row in plan] == [
        (row["plan_id"], row["requested_entry"]) for row in records
    ]
    assert records[0]["parameters"][0]["type"]["kind"] == "pointer"
    assert records[0]["signature_source"] == "USER_DEFINED"

    exporter = (ROOT / "ghidra/ExportGhidraFunctionPrototypes.java").read_text()
    runner = (ROOT / "scripts/run_ghidra_function_prototypes.sh").read_text()
    for expected in (
        '"REVENGINSTR.GhidraFunctionPrototype/1"',
        "getExecutableSHA256()",
        "getSignatureSource()",
        "getDefaultPointerSize()",
        "getParameters()",
        "getReturnType()",
        "getCallingConventionName()",
    ):
        assert expected in exporter
    assert "-readOnly" in runner and "-noanalysis" in runner
    assert "Ghidra function prototype export complete:" in runner
    for forbidden in ("Nevergone", "EnemyObject", "SHIFT", "dispatch_slot_offset"):
        assert forbidden not in exporter
