from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]


def test_batch_pcode_exporter_keeps_existing_contracts_and_fails_closed() -> None:
    source = (ROOT / "ghidra/ExportProgramPcodeFlowBatch.java").read_text(encoding="utf-8")
    for required in (
        '"REVENGINSTR.GhidraIndirectCallEvidence/1"',
        '"REVENGINSTR.GhidraPcodeFlowAcquisition/1"',
        '"function_entry\\top_address\\top_time\\topcode\\toutput\\tinputs\\tcallee_entry\\tcallee_name"',
        '"decompile_failed"',
        '"no_pcode"',
        '"complete"',
        "PcodeOp.CALLIND",
        "MAX_EXPRESSION_DEPTH = 6",
        "{depth-limit}",
        "{cycle}",
        "function list exceeds max-functions=",
        "batch exceeded max-total-seconds=",
        "function not found at exact entry:",
    ):
        assert required in source
    for consumer_term in ("Nevergone", "NEVERGONE", "SHIFT", "EnemyObject", "HDVehicle"):
        assert consumer_term not in source

    runner = (ROOT / "scripts/run_ghidra_pcode_flow_batch.sh").read_text(encoding="utf-8")
    assert "-readOnly" in runner
    assert "-noanalysis" in runner
    assert "mktemp -d" in runner
    assert "GHIDRA_PROGRAM_PCODE_FLOW_FORMAT=REVENGINSTR.GhidraPcodeFlowAcquisition/1" in runner


def test_batch_acquisition_schema() -> None:
    schema = json.loads((ROOT / "schemas/ghidra-pcode-flow-acquisition-v1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    for state, error in (("complete", None), ("no_pcode", None), ("decompile_failed", "timeout")):
        validator.validate({
            "format": "REVENGINSTR.GhidraPcodeFlowAcquisition/1",
            "program": "sample",
            "function_entry": "0x00401000",
            "state": state,
            "operation_count": 0,
            "callind_count": 0,
            "error": error,
        })


def test_batch_runner_is_valid_shell() -> None:
    import subprocess

    runner = ROOT / "scripts/run_ghidra_pcode_flow_batch.sh"
    subprocess.run(["bash", "-n", str(runner)], check=True)
    assert runner.stat().st_mode & 0o111
