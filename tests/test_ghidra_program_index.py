from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_program_index_contract_is_generic() -> None:
    source = (ROOT / "ghidra/ExportGhidraProgramIndex.java").read_text(encoding="utf-8")
    for required in (
        "ExportGhidraProgramIndex.java <output-path-prefix>",
        '"functions", "entry\\tname\\taddress_count\\tis_external\\tsignature"',
        '"symbols", "address\\tname\\ttype\\tsource\\tis_primary"',
        '"strings", "address\\tutf8_base64\\tlength"',
        '"xrefs", "from\\tto\\ttype\\toperand\\tsource"',
        '"calls", "caller_entry\\tcall_site\\tcallee_entry"',
        "getReferenceType().isCall()",
    ):
        assert required in source
    for consumer_term in ("Nevergone", "NEVERGONE", "SHIFT", "EnemyObject", "HDVehicle"):
        assert consumer_term not in source


def test_program_index_runner_is_read_only_and_isolated() -> None:
    runner = (ROOT / "scripts/run_ghidra_program_index.sh").read_text(encoding="utf-8")
    assert "-readOnly" in runner
    assert "-noanalysis" in runner
    assert "mktemp -d" in runner
    assert "ExportGhidraProgramIndex.java" in runner
