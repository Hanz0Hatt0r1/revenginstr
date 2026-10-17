from __future__ import annotations

import gzip
import hashlib
import json
import shutil
from pathlib import Path

import pytest

from revenginstr.pcode.c_lowering_corpus import build


def _varnode(space: str, offset: str, size: int, *, constant: bool = False) -> dict:
    return {"space": space, "offset": offset, "size": size, "constant": constant}


def _return_row(address: str) -> dict:
    return {
        "format": "REVENGINSTR.GhidraFunctionInstructions/1",
        "program": "sample.exe",
        "requested": address,
        "resolved_address": address,
        "found": True,
        "function": {"address": address, "name": "sample", "size": 1, "calling_convention": None},
        "instruction_count": 1,
        "instructions": [{
            "address": address, "mnemonic": "RET", "flow_type": "TERMINATOR", "flows": [],
            "pcode": [{
                "opcode": "RETURN", "output": None,
                "inputs": [_varnode("register", "0x20", 4)],
            }],
        }],
    }


def test_corpus_builder_compiles_shared_runtime_object_shards(tmp_path: Path) -> None:
    compiler = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if compiler is None:
        pytest.skip("C compiler not available")

    rows = [_return_row(f"0x004010{index * 0x10:02x}") for index in range(3)]
    unsupported = _return_row("0x00401400")
    unsupported["instructions"] = [{
        "address": "0x00401400", "mnemonic": "MOV", "flow_type": "FALL_THROUGH", "flows": [],
        "pcode": [{
            "opcode": "COPY", "output": _varnode("register", "0x4", 9),
            "inputs": [_varnode("const", "0x0", 9, constant=True)],
        }],
    }]
    rows.append(unsupported)

    corpus = tmp_path / "functions.jsonl.gz"
    with gzip.open(corpus, "wt", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row) + "\n")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({
        "format": "REVENGINSTR.GhidraFunctionInstructionCorpus/1",
        "program": "sample.exe",
        "language_id": "x86:LE:32:default",
        "exported_function_count": len(rows),
        "instruction_count": len(rows),
        "output_sha256": hashlib.sha256(corpus.read_bytes()).hexdigest(),
    }), encoding="utf-8")
    spaces = tmp_path / "address-spaces.json"
    spaces.write_text(json.dumps({
        "format": "REVENGINSTR.GhidraLanguageAddressSpaces/1",
        "language_id": "x86:LE:32:default",
        "big_endian": False,
        "default_space": "ram",
        "address_spaces": [],
    }), encoding="utf-8")
    output = tmp_path / "objects"

    report = build(corpus, manifest, spaces, output, compiler, shard_size=2, jobs=2)

    assert report["functions"] == {
        "records": 4, "found": 4, "missing": 0, "lowerable": 3, "rejected": 1,
    }
    assert [shard["functions"] for shard in report["shards"]] == [2, 1]
    assert report["jobs"] == 2
    assert report["rejection_reasons"] == [{
        "reason": "scalar varnode size 9 exceeds 8-byte limit", "functions": 1,
    }]
    first_source = (output / "shard-00000.c").read_text(encoding="utf-8")
    assert first_source.count("typedef struct {") == 1
    assert "int rvi_00401000" in first_source and "int rvi_00401010" in first_source
    assert all((output / shard["object_file"]).stat().st_size > 0 for shard in report["shards"])
    assert json.loads((output / "build-report.json").read_text(encoding="utf-8")) == report
