from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]


def test_language_userop_export_contract() -> None:
    source = (ROOT / "ghidra/ExportGhidraLanguageUserops.java").read_text(encoding="utf-8")
    assert '"REVENGINSTR.GhidraLanguageUserops/1"' in source
    assert "getNumberOfUserDefinedOpNames()" in source
    assert "getUserDefinedOpName(i)" in source
    for consumer_term in ("Nevergone", "SHIFT", "HDVehicle", "EnemyObject"):
        assert consumer_term not in source

    schema = json.loads((ROOT / "schemas/ghidra-language-userops-v1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate({
        "format": "REVENGINSTR.GhidraLanguageUserops/1",
        "language_id": "x86:LE:32:default",
        "userop_count": 3,
        "userops": [
            {"index": 0, "name": "segment_base"},
            {"index": 1, "name": None},
            {"index": 2, "name": "halt"},
        ],
    })


def test_language_userop_runner_uses_read_only_program_and_isolated_script() -> None:
    runner = (ROOT / "scripts/run_ghidra_language_userops.sh").read_text(encoding="utf-8")
    assert "-readOnly" in runner
    assert "-noanalysis" in runner
    assert "mktemp -d" in runner
    assert "ExportGhidraLanguageUserops.java" in runner
    assert "userop count mismatch" in runner
