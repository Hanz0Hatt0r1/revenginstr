from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPORTERS = (
    ROOT / "ghidra/ExportBoundedCallGraphPcodeFlow.java",
    ROOT / "ghidra/ExportBoundedReverseCallGraphPcodeFlow.java",
)
TSV_HEADER = (
    "function_entry\\top_address\\top_time\\topcode\\toutput\\tinputs\\t"
    "callee_entry\\tcallee_name"
)


def test_bounded_pcode_exporters_are_generic_and_configurable() -> None:
    for path in EXPORTERS:
        source = path.read_text(encoding="utf-8")
        assert TSV_HEADER in source
        assert "configurePriorities(args" in source
        assert "--default-priority=" in source
        assert "--priority=" in source
        for consumer_term in ("Nevergone", "EnemyObject", "EnemyActionsSystem", "cocos2d::"):
            assert consumer_term not in source
