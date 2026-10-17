from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


def test_instruction_slice_export_contract() -> None:
    source = (ROOT / "ghidra/ExportGhidraInstructionSlices.java").read_text(encoding="utf-8")
    for required in (
        '"REVENGINSTR.GhidraInstructionSlice/1"',
        "listing.getInstructionAt(start)",
        "new AddressSet(start, end)",
        "instruction.getPcode()",
        "instruction.getReferencesFrom()",
        "instruction.getFlows()",
        "node.isConstant()",
        "node.isRegister()",
    ):
        assert required in source
    for consumer_term in ("SHIFT", "Nevergone", "HDVehicle", "GameScene"):
        assert consumer_term not in source

    schema = json.loads((ROOT / "schemas/ghidra-instruction-slice-v1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    fixture = json.loads(
        (ROOT / "tests/fixtures/ghidra-instructions/instruction-slice.json").read_text(encoding="utf-8")
    )
    validator.validate(fixture)
    validator.validate({
        "format": "REVENGINSTR.GhidraInstructionSlice/1",
        "program": "sample.bin",
        "requested": "0x00402000",
        "start": "0x00402000",
        "length": 128,
        "exact_instruction_at_start": False,
        "instruction_count": 0,
        "instructions": [],
    })


def test_instruction_slice_runner_is_read_only_recursive_and_isolated() -> None:
    runner = (ROOT / "scripts/run_ghidra_instruction_slices.sh").read_text(encoding="utf-8")
    for required in ("-recursive", "-readOnly", "-noanalysis", "mktemp -d", "ExportGhidraInstructionSlices.java"):
        assert required in runner
