from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]


def test_function_pcode_cfg_contract_has_ordered_operations_and_edges() -> None:
    schema = json.loads((ROOT / "schemas/ghidra-function-pcode-cfg-v1.schema.json").read_text(encoding="utf-8"))
    fixture = json.loads(
        (ROOT / "tests/fixtures/function-pcode-cfg/synthetic.jsonl").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(fixture)
    assert [block["block_index"] for block in fixture["blocks"]] == [0, 1, 2, 3]
    assert fixture["blocks"][0]["operations"][0]["opcode"] == "STORE"
    assert fixture["blocks"][0]["successors"] == [1, 2]


def test_generic_pcode_cfg_exporter_and_runner_contract() -> None:
    source = (ROOT / "ghidra/ExportFunctionPcodeCFG.java").read_text(encoding="utf-8")
    runner = (ROOT / "scripts/run_ghidra_function_pcode_cfg.sh").read_text(encoding="utf-8")
    assert "high.getBasicBlocks()" in source
    assert "program_id" in source
    assert "block.getIterator()" in source
    assert "block.getOut(edge)" in source
    assert "--memory-metadata" in source
    assert "entry_block_index" in source
    assert "memory_width_bytes" in source
    assert "getAddressSpace((int) offset)" in source
    assert "-readOnly" in runner and "-noanalysis" in runner
    for forbidden in ("Nevergone", "GameScene", "HDVehicle", "SHIFT"):
        assert forbidden not in source
