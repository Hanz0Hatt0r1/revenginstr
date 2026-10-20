from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_arm32_itanium_vtable_export_is_project_neutral_and_read_only() -> None:
    source = (ROOT / "ghidra/ExportArm32ItaniumVtableSlots.java").read_text()

    required = (
        "ADDRESS_POINT_DELTA = 8",
        "POINTER_SIZE = 4",
        "UINT32_MASK = 0xffffffffL",
        "memory.getInt(slotAddress)",
        "(rawValue & UINT32_MASK) & ~1L",
        "currentProgram.getImageBase().getOffset()",
        "checkedAddress(canonical)",
        "checkedBiasedOffset(canonical, imageBase)",
        "Long.compareUnsigned(slotLong, nextStart) >= 0",
        "REVENGINSTR.GhidraArm32ItaniumVtableSlots/1",
        "next_vtable_symbol_start",
        "symbol.getName()",
        "target.getName()",
        'leaf.startsWith("_ZTC")',
    )
    assert all(fragment in source for fragment in required)
    assert "getName(true)" not in source
    assert source.index("if (symbol.isDynamic()) continue;") < source.index("String name = symbol.getName();")
    assert all(name not in source for name in ("Nevergone", "NEVERGONE", "SHIFT", "libcocos"))
    assert all(name not in source for name in ("setBytes(", "setInt(", "createFunction(", "removeFunction("))


def test_vtable_runner_is_read_only_and_uses_shared_exporter() -> None:
    runner = (ROOT / "scripts/run_ghidra_vtable_slots.sh").read_text()
    assert "-readOnly" in runner
    assert "-noanalysis" in runner
    assert "TMP_SCRIPT_DIR" in runner
    assert "VTABLE_SLOT_FORMAT=REVENGINSTR.GhidraArm32ItaniumVtableSlots/1" in runner
    assert "ExportArm32ItaniumVtableSlots.java" in runner
