# Ghidra pointer-table slot export

`ExportGhidraPointerTableSlots.java` exports a caller-selected, bounded range of
pointer-sized slots from an already analyzed Ghidra program. It makes no C++
ABI, vtable, class, or call-target assumption. Each row records the raw slot
bytes, decoded pointer value, mapped target address, and exact Ghidra function
entry when one exists. A mapped non-function pointer remains data; invalid or
unreadable values have explicit statuses.

The exporter opens the selected program read-only and disables analysis. Table
bases and slot counts are explicit inputs, limited to 64 tables and 4096 slots
per table. It supports default pointer widths of four or eight bytes. Slots are
emitted in input order and ascending offset. The program id is supplied by the
caller and should bind the output to a pinned program identity. Raw pointer
values are not rebased or normalized for architecture-specific tag bits; a
function is attached only when that exact address is a Ghidra function entry.
The fixed JSONL contract is
[`GhidraPointerTableSlots/1`](../schemas/ghidra-pointer-table-slots-v1.schema.json).

For example, inspect two 32-bit SHIFT tables without inferring what the objects
or methods mean:

```sh
scripts/run_ghidra_pointer_table_slots.sh \
  /home/pes/ghidra_projects/shift shift SHIFT.exe /tmp/shift-pointer-tables.jsonl \
  'nfs-shift:SHIFT.exe:eca479aa2d8dbb88bc55709d91ae5c7159ae1b00fc9555d6701000c26de8aee1' \
  0x00af0860 16 0x00af08a0 16
```

The output preserves every requested slot, including nulls and holes. It does
not prove that a particular object uses a table, that a table is a vtable, or
that a call site dispatches through a given slot. Those relationships require
separate receiver-population evidence.
