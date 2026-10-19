from __future__ import annotations

import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/ghidra-decompiler-parameters"


def test_real_decompiler_parameter_replay_matches_schema_and_source_flow() -> None:
    schema = json.loads((ROOT / "schemas/ghidra-decompiler-parameters-v1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    records = [json.loads(line) for line in (FIXTURES / "decompiler-parameters.jsonl").read_text().splitlines()]
    validator = Draft202012Validator(schema)
    for record in records:
        validator.validate(record)
        assert record["status"] == "complete"
        assert record["parameter_count"] == len(record["parameters"])
    assert records[0]["name"] == "sample_add"
    assert [param["type"]["kind"] for param in records[0]["parameters"]] == ["pointer", "scalar"]
    assert records[0]["return_type"]["kind"] == "pointer"

    flow = (FIXTURES / "sample-caller-flow.tsv").read_bytes()
    call = json.loads((FIXTURES / "call-observations.jsonl").read_text().splitlines()[0])
    assert call["evidence_ref"]["artifact_sha256"] == hashlib.sha256(flow).hexdigest()
    assert call["callee_entry"] == records[0]["function_entry"]
    assert call["argument_count"] == records[0]["parameter_count"]

    exporter = (ROOT / "ghidra/ExportGhidraDecompilerParameters.java").read_text()
    runner = (ROOT / "scripts/run_ghidra_decompiler_parameters.sh").read_text()
    for expected in (
        '"REVENGINSTR.GhidraDecompilerParameters/1"', "getLocalSymbolMap()",
        "getParamSymbol(index)", "isThisPointer()", "isHiddenReturn()", "getExecutableSHA256()",
        "Undefined.isUndefined(type)", "Undefined.isUndefinedArray(type)",
    ):
        assert expected in exporter
    assert "-readOnly" in runner and "-noanalysis" in runner
    assert "GHIDRA_DECOMPILER_PARAMETERS_FORMAT=" in runner
    for forbidden in ("Nevergone", "EnemyObject", "SHIFT", "dispatch_slot_offset"):
        assert forbidden not in exporter
