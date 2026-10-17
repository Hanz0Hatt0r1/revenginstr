from __future__ import annotations

import gzip
import hashlib
import json
from pathlib import Path

from revenginstr.pcode.c_lowering_coverage import audit


def test_coverage_audit_hash_pins_inputs_and_counts_lowerable_functions(tmp_path: Path) -> None:
    corpus = tmp_path / "functions.jsonl.gz"
    row = {
        "format": "REVENGINSTR.GhidraFunctionInstructions/1",
        "program": "sample.exe",
        "requested": "0x00401000",
        "resolved_address": "0x00401000",
        "found": True,
        "function": {"address": "0x00401000", "name": "sample", "size": 1, "calling_convention": None},
        "instruction_count": 1,
        "instructions": [{
            "address": "0x00401000", "mnemonic": "RET", "flow_type": "TERMINATOR", "flows": [],
            "pcode": [{
                "opcode": "RETURN", "output": None,
                "inputs": [{"space": "register", "offset": "0x20", "size": 4, "constant": False}],
            }],
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
    spaces = tmp_path / "address-spaces.json"
    spaces.write_text(json.dumps({
        "format": "REVENGINSTR.GhidraLanguageAddressSpaces/1",
        "language_id": "x86:LE:32:default",
        "big_endian": False,
        "default_space": "ram",
        "default_data_space": "ram",
        "address_spaces": [],
    }), encoding="utf-8")

    report = audit(corpus, manifest, spaces)

    assert report["format"] == "REVENGINSTR.PcodeCFunctionLoweringCoverage/1"
    assert report["source"]["corpus_sha256"] == hashlib.sha256(corpus.read_bytes()).hexdigest()
    assert report["functions"] == {
        "records": 1, "found": 1, "missing": 0, "fully_lowerable": 1, "rejected": 0,
    }
    assert report["pcode_operations"]["in_fully_lowerable_functions"] == 1
