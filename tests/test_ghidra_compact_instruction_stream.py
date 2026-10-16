from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
FORMAT = "REVENGINSTR.GhidraCompactInstructionStream/1"


def test_compact_instruction_stream_schema_and_generic_boundary() -> None:
    source = (ROOT / "ghidra/ExportGhidraCompactInstructionStream.java").read_text(encoding="utf-8")
    for required in ('"' + FORMAT + '"', "listing.getInstructions(true)", "GZIPOutputStream", "getExecutableMD5()", "getLanguageID()"):
        assert required in source
    for consumer_term in ("SHIFT", "Nevergone", "HDVehicle", "GameScene", "Process 1"):
        assert consumer_term not in source

    schema = json.loads((ROOT / "schemas/ghidra-compact-instruction-stream-v1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    validator.validate({
        "format": FORMAT,
        "kind": "header",
        "program": "sample.bin",
        "executable_md5": "0123456789abcdef0123456789abcdef",
        "language_id": "x86:LE:64:default",
        "image_base": "0x00400000",
        "pointer_size": 8,
    })
    validator.validate({
        "format": FORMAT,
        "kind": "instruction",
        "address": "0x00401000",
        "mnemonic": "CALL",
        "operands": ["FUN_00402000"],
        "flow_type": "CALL",
        "flows": ["0x00402000"],
    })


def test_compact_instruction_stream_runner_is_read_only_isolated_and_gzip_aware() -> None:
    runner = (ROOT / "scripts/run_ghidra_compact_instruction_stream.sh").read_text()
    for required in ("-readOnly", "-noanalysis", "mktemp -d", "gzip.open", ".gz", "REVENGINSTR.GhidraCompactInstructionStream/1"):
        assert required in runner
