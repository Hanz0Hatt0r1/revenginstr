from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.pcode.address_space_coverage import audit


ROOT = Path(__file__).resolve().parents[1]


def _inputs(tmp_path: Path) -> tuple[Path, Path, Path]:
    corpus = tmp_path / "functions.jsonl.gz"
    row = {
        "format": "REVENGINSTR.GhidraFunctionInstructions/1",
        "program": "sample.exe",
        "found": True,
        "function": {"address": "0x00401000", "name": "sample", "size": 1, "calling_convention": None},
        "instruction_count": 1,
        "instructions": [{"pcode": [
            {"opcode": "LOAD", "inputs": [
                {"space": "const", "offset": "0x1a1", "constant": True},
                {"space": "register", "offset": "0x10", "constant": False},
            ]},
            {"opcode": "STORE", "inputs": [
                {"space": "const", "offset": "0x1a1", "constant": True},
                {"space": "register", "offset": "0x10", "constant": False},
                {"space": "unique", "offset": "0x1", "constant": False},
            ]},
            {"opcode": "STORE", "inputs": [
                {"space": "const", "offset": "0x2b0", "constant": True},
                {"space": "register", "offset": "0x10", "constant": False},
                {"space": "unique", "offset": "0x1", "constant": False},
            ]},
        ]}],
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
    spaces = tmp_path / "spaces.json"
    spaces.write_text(json.dumps({
        "format": "REVENGINSTR.GhidraLanguageAddressSpaces/1",
        "language_id": "x86:LE:32:default",
        "address_spaces": [{"space_id": "0x1a1", "name": "ram"}],
    }), encoding="utf-8")
    return corpus, manifest, spaces


def test_address_space_coverage_maps_load_store_ids_and_reports_unknowns(tmp_path: Path) -> None:
    corpus, manifest, spaces = _inputs(tmp_path)
    report = audit(corpus, manifest, spaces)

    assert report["corpus"]["load_operations"] == 1
    assert report["corpus"]["store_operations"] == 2
    assert report["used_address_spaces"] == [{
        "name": "ram",
        "space_id": "0x1a1",
        "load_operations": 1,
        "store_operations": 1,
        "operations": 2,
    }]
    assert report["unmapped_address_spaces"] == [{
        "space_id": "0x2b0",
        "load_operations": 0,
        "store_operations": 1,
        "operations": 1,
    }]
    schema = json.loads((ROOT / "schemas/pcode-address-space-coverage-v1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(report)


def test_address_space_coverage_rejects_language_or_corpus_hash_mismatch(tmp_path: Path) -> None:
    corpus, manifest, spaces = _inputs(tmp_path)
    data = json.loads(spaces.read_text())
    data["language_id"] = "arm:LE:32:v7"
    spaces.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="language_id"):
        audit(corpus, manifest, spaces)

    data["language_id"] = "x86:LE:32:default"
    spaces.write_text(json.dumps(data), encoding="utf-8")
    data = json.loads(manifest.read_text())
    data["output_sha256"] = "0" * 64
    manifest.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ValueError, match="SHA-256"):
        audit(corpus, manifest, spaces)
