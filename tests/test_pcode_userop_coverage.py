from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.pcode.userop_coverage import audit


ROOT = Path(__file__).resolve().parents[1]


def test_userop_coverage_joins_corpus_ids_to_language_names(tmp_path: Path) -> None:
    corpus = tmp_path / "functions.jsonl.gz"
    row = {
        "format": "REVENGINSTR.GhidraFunctionInstructions/1",
        "program": "sample.exe",
        "requested": "0x00401000",
        "resolved_address": "0x00401000",
        "found": True,
        "function": {"address": "0x00401000", "name": "FUN_00401000", "size": 1, "calling_convention": None},
        "instruction_count": 1,
        "instructions": [{
            "address": "0x00401000", "mnemonic": "FPU", "pcode": [
                {"opcode": "CALLOTHER", "inputs": [
                    {"space": "const", "offset": "0x2", "constant": True}
                ]},
                {"opcode": "CALLOTHER", "inputs": [
                    {"space": "const", "offset": "0x9", "constant": True}
                ]},
            ]
        }],
    }
    with gzip.open(corpus, "wt", encoding="utf-8") as stream:
        stream.write(json.dumps(row) + "\n")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({
        "format": "REVENGINSTR.GhidraFunctionInstructionCorpus/1",
        "program": "sample.exe",
        "language_id": "x86:LE:32:default",
        "exported_function_count": 1,
        "instruction_count": 1,
        "output_sha256": hashlib.sha256(corpus.read_bytes()).hexdigest(),
    }), encoding="utf-8")
    userops = tmp_path / "userops.json"
    userops.write_text(json.dumps({
        "format": "REVENGINSTR.GhidraLanguageUserops/1",
        "language_id": "x86:LE:32:default",
        "userop_count": 3,
        "userops": [
            {"index": 0, "name": "zero"},
            {"index": 1, "name": None},
            {"index": 2, "name": "known"},
        ],
    }), encoding="utf-8")

    report = audit(corpus, manifest, userops)

    assert report["corpus"]["callother_operations"] == 2
    assert report["used_userops"] == [{"index": 2, "name": "known", "uses": 1}]
    assert report["unmapped_userops"] == [{"index": 9, "uses": 1}]
    schema = json.loads((ROOT / "schemas/pcode-userop-coverage-v1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(report)


def test_userop_coverage_rejects_language_or_corpus_hash_mismatch(tmp_path: Path) -> None:
    corpus = tmp_path / "functions.jsonl"
    row = {
        "format": "REVENGINSTR.GhidraFunctionInstructions/1",
        "program": "sample.exe",
        "instruction_count": 0,
        "instructions": [],
    }
    corpus.write_text(json.dumps(row) + "\n", encoding="utf-8")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({
        "format": "REVENGINSTR.GhidraFunctionInstructionCorpus/1",
        "program": "sample.exe",
        "language_id": "x86:LE:32:default",
        "exported_function_count": 1,
        "instruction_count": 0,
        "output_sha256": "0" * 64,
    }), encoding="utf-8")
    userops = tmp_path / "userops.json"
    userops.write_text(json.dumps({
        "format": "REVENGINSTR.GhidraLanguageUserops/1",
        "language_id": "arm:LE:32:v7",
        "userop_count": 0,
        "userops": [],
    }), encoding="utf-8")
    with pytest.raises(ValueError, match="SHA-256"):
        audit(corpus, manifest, userops)
