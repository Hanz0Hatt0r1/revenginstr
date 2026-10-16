from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


def test_generic_defined_string_export_contract() -> None:
    source = (ROOT / "ghidra/ExportGhidraPcodeDefinedStrings.java").read_text(encoding="utf-8")
    for required in (
        '"REVENGINSTR.GhidraPcodeDefinedString/1"',
        'Pattern.compile("const:0x([0-9a-fA-F]+):[0-9]+")',
        "getDefinedDataContaining(address)",
        "data.getValue() instanceof String",
        "Base64.getEncoder()",
    ):
        assert required in source
    for consumer_term in ("Nevergone", "EnemyObject", "SHIFT", "GameScene", "class_name"):
        assert consumer_term not in source

    schema = json.loads(
        (ROOT / "schemas/ghidra-pcode-defined-strings-v1.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate({
        "format": "REVENGINSTR.GhidraPcodeDefinedString/1",
        "constant_address": "0x401000",
        "data_address": "00401000",
        "byte_offset": "0x0",
        "utf8_base64": "aGVsbG8=",
        "length": "5",
    })


def test_defined_string_runner_is_read_only_and_isolated() -> None:
    runner = (ROOT / "scripts/run_ghidra_pcode_defined_strings.sh").read_text(encoding="utf-8")
    assert "-readOnly" in runner
    assert "-noanalysis" in runner
    assert "mktemp -d" in runner
    assert "ExportGhidraPcodeDefinedStrings.java" in runner
