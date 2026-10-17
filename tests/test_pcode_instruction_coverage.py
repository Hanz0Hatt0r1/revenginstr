from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.pcode.coverage import audit


ROOT = Path(__file__).resolve().parents[1]


def row(requested: str, instructions: list[dict]) -> dict:
    return {
        "format": "REVENGINSTR.GhidraFunctionInstructions/1",
        "program": "sample.exe",
        "requested": requested,
        "resolved_address": requested,
        "found": True,
        "function": {
            "address": requested,
            "name": f"FUN_{requested[2:]}",
            "size": 8,
            "calling_convention": "__cdecl",
        },
        "instruction_count": len(instructions),
        "instructions": instructions,
    }


def instruction(address: str, mnemonic: str, opcodes: list[str]) -> dict:
    return {
        "address": address,
        "bytes": "90",
        "mnemonic": mnemonic,
        "text": mnemonic,
        "operands": [],
        "flow_type": "FALL_THROUGH",
        "fallthrough": None,
        "flows": [],
        "references": [],
        "pcode": [{"opcode": opcode, "text": opcode, "output": None, "inputs": []} for opcode in opcodes],
    }


def test_instruction_coverage_streams_gzip_and_validates_schema(tmp_path: Path) -> None:
    corpus = tmp_path / "functions.jsonl.gz"
    rows = [
        row("0x00401000", [instruction("0x00401000", "MOV", ["COPY", "INT_ADD"])]),
        row("0x00401008", [instruction("0x00401008", "NOP", [])]),
    ]
    with gzip.open(corpus, "wt", encoding="utf-8") as stream:
        for item in rows:
            stream.write(json.dumps(item) + "\n")

    report = audit(corpus)

    assert report["functions"] == {"records": 2, "found": 2, "missing": 0}
    assert report["instructions"] == {
        "total": 2,
        "with_pcode": 1,
        "without_pcode": 1,
        "without_pcode_mnemonics": {"NOP": 1},
    }
    assert report["pcode"] == {
        "operations": 2,
        "unique_opcodes": 2,
        "opcode_counts": {"COPY": 1, "INT_ADD": 1},
    }
    schema = json.loads((ROOT / "schemas/pcode-instruction-coverage-v1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(report)


def test_instruction_coverage_rejects_mixed_program_and_count_drift(tmp_path: Path) -> None:
    corpus = tmp_path / "functions.jsonl"
    first = row("0x00401000", [instruction("0x00401000", "RET", ["RETURN"])])
    second = row("0x00401008", [])
    second["program"] = "other.exe"
    corpus.write_text(json.dumps(first) + "\n" + json.dumps(second) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="mixed program"):
        audit(corpus)

    second["program"] = "sample.exe"
    second["instruction_count"] = 1
    corpus.write_text(json.dumps(first) + "\n" + json.dumps(second) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="instruction_count"):
        audit(corpus)
