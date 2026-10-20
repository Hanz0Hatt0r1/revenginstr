from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


def test_generic_function_instruction_contract() -> None:
    source = (ROOT / "ghidra/ExportGhidraFunctionInstructions.java").read_text(encoding="utf-8")
    for required in (
        '"REVENGINSTR.GhidraFunctionInstructions/1"',
        "listing.getInstructions(function.getBody(), true)",
        "instruction.getPcode()",
        "instruction.getReferencesFrom()",
        "instruction.getFlows()",
        "node.isConstant()",
        "node.isRegister()",
    ):
        assert required in source
    for consumer_term in ("Nevergone", "SHIFT", "EnemyObject", "nearby_class_evidence"):
        assert consumer_term not in source

    schema = json.loads(
        (ROOT / "schemas/ghidra-function-instructions-v1.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    fixture = json.loads(
        (ROOT / "tests/fixtures/ghidra-instructions/function-instructions.json").read_text(encoding="utf-8")
    )
    validator.validate(fixture)
    validator.validate({
        "format": "REVENGINSTR.GhidraFunctionInstructions/1",
        "program": "sample",
        "requested": "00402000",
        "resolved_address": "0x00402000",
        "found": False,
        "function": None,
        "instruction_count": 0,
        "instructions": [],
    })
    validator.validate({
        "format": "REVENGINSTR.GhidraFunctionInstructions/1",
        "program": "sample",
        "requested": "entry:0x00401000",
        "resolved_address": "0x00401000",
        "found": True,
        "function": {
            "address": "0x00401000",
            "name": "ENTRY_00401000",
            "size": 1,
            "calling_convention": None,
        },
        "instruction_count": 1,
        "instructions": [fixture["instructions"][0]],
    })


def test_exporter_restores_only_verified_returning_call_fallthroughs() -> None:
    source = (ROOT / "ghidra/ExportGhidraFunctionInstructions.java").read_text(encoding="utf-8")
    for required in (
        "collectFunctionInstructions",
        "PseudoDisassembler",
        '"entry:"',
        "writeEntrypointRow",
        "listing.getInstructionAt(address)",
        "instruction.getFlowType().toString()",
        '"CALL_TERMINATOR"',
        '"UNCONDITIONAL_CALL"',
        "operation.getOpcode() == PcodeOp.RETURN",
        "addRecoverySuccessors",
        "MAX_RECOVERED_BYTES",
        "exceeded the ",
        "instruction budget",
    ):
        assert required in source
    for consumer_term in ("Nevergone", "SHIFT.exe", "__fload_withFB", "0x00902ec7"):
        assert consumer_term not in source


def test_function_instruction_runner_is_read_only_and_isolated() -> None:
    runner = (ROOT / "scripts/run_ghidra_function_instructions.sh").read_text(encoding="utf-8")
    assert "-readOnly" in runner
    assert "-noanalysis" in runner
    assert "mktemp -d" in runner
    assert "ExportGhidraFunctionInstructions.java" in runner


def test_full_function_corpus_export_is_streamed_and_hash_pinned() -> None:
    source = (ROOT / "ghidra/ExportGhidraFunctionInstructions.java").read_text(encoding="utf-8")
    for required in (
        '"--all".equals(args[1])',
        "functions.getFunctions(true)",
        "GZIPOutputStream",
        "function_offset",
        "exported_function_count",
        "output_sha256",
    ):
        assert required in source
    assert "StringWriter" not in source

    schema = json.loads(
        (ROOT / "schemas/ghidra-function-instruction-corpus-v1.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate({
        "format": "REVENGINSTR.GhidraFunctionInstructionCorpus/1",
        "program": "sample",
        "executable_md5": "0123456789abcdef0123456789abcdef",
        "language_id": "x86:LE:32:default",
        "function_count": 10,
        "function_offset": 0,
        "function_limit": 10,
        "exported_function_count": 10,
        "instruction_count": 120,
        "first_function_address": "0x00401000",
        "last_function_address": "0x00402000",
        "complete": True,
        "gzip": True,
        "output_sha256": "a" * 64,
    })
