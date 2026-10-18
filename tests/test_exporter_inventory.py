import re
from pathlib import Path


def test_canonical_ghidra_inventory_lists_every_java_exporter():
    root = Path(__file__).resolve().parents[1]
    inventory = (root / "docs/EXPORTER_INVENTORY.md").read_text(encoding="utf-8")
    section = inventory.split("## Canonical Ghidra surface in `revenginstr`", 1)[1]
    section = section.split("## Follow-up from this snapshot", 1)[0]
    listed = re.findall(r"`((?:Export|PortablePcodeCorpusExporter)[A-Za-z0-9]*)`", section)
    sources = {path.stem for path in (root / "ghidra").glob("*.java")}

    assert len(listed) == len(set(listed))
    assert set(listed) == sources
