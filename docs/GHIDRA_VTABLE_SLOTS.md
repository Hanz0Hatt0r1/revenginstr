# ARM32 Itanium vtable slot export

`ExportArm32ItaniumVtableSlots.java` writes a gzip-compressed UTF-8 TSV for
conservatively resolved primary ARM32 Itanium vtable slots. The row contract is
[`REVENGINSTR.GhidraArm32ItaniumVtableSlots/1`](../schemas/ghidra-arm32-itanium-vtable-slots-v1.schema.json).
The fixed header is (each `\t` below is one tab delimiter):

```text
vtable_symbol_start\tvtable_symbol_name\taddress_point\tslot_offset\tslot_address\traw_value\ttarget_thumb\ttarget_entry\ttarget_name\ttarget_signature\tresolution_mode\tnext_vtable_symbol_start
```

All wire cells are strings. The numeric
addresses and offsets emitted by the exporter use lowercase `0x` hexadecimal;
`target_thumb` is `true` or `false`; and the final vtable's next-start cell is
`-`. The command also prints `VTABLE_SLOT_FORMAT=REVENGINSTR.GhidraArm32ItaniumVtableSlots/1`
as invocation metadata. Program addresses, symbol names and signatures are
provenance from the selected Ghidra database; keep program identity alongside
the output because the row has no program field.

Vtable symbols are de-duplicated by start address (preferring a primary symbol)
and sorted by start address. Each address point is symbol start +8. Slots are
visited in ascending four-byte offsets up to the requested bound (default
`0x400`); the contiguous walk stops at the first zero, unreadable, out-of-memory,
or non-function pointer. Function pointers are normalized by clearing the ARM
Thumb bit and resolved first as a Ghidra address, then as image-base plus module
offset. The resolution mode is explicit in each row.

The exporter opens an already analyzed project read-only with analysis disabled.
Invalid bounds or headless execution errors fail the command. A table with no
resolved slots is a valid header-only output. The TSV header and row meanings
are fixed for v1; incompatible changes require a new schema/version.

```sh
GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_vtable_slots.sh \
  /path/to/project project-name program-name /tmp/vtables.tsv.gz 0x400
```
