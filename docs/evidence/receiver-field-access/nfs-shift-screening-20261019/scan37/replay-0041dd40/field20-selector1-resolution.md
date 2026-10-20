# Selector-1 `+0x74` vtable replay

**Capture date:** 2026-10-20. **Target:** retail `SHIFT.exe`, SHA-256
`eca479aa2d8dbb88bc55709d91ae5c7159ae1b00fc9555d6701000c26de8aee1`.
The saved SHIFT Ghidra project was read-only with analysis disabled (Ghidra
12.1.2, Java 21.0.12.1). This replay follows a static constructor path; it does
not claim that selector 1 or any specific constructor is observed at runtime.

## Getter case and observed constructor paths

The retained getter excerpt shows selector 1 returning `parent + 0x74` in both
`00676040` and `006770b0`. The High-P-code caller flow leaves the selector at
`Stack[0x4]`. Wrapper `0064a0c0` obtains it through `00648d50`, which reads the
input record's bytes at `+1`, `+2`, and sometimes `+3`; the value is data
-dependent. The address-reference export records the wrapper and method
references used to bound this chain.

Four constructor roots from the cached-field candidate set initialize that
member before setting their final primary vtable:

| Getter candidate | Root constructor | Factory call | Final primary vtable | `+0x74` initializer path |
| --- | --- | --- | --- | --- |
| `00676040` | `00672320` | `0066f208` | `00af6a50` | `00672320` → `00676650` → `00678b90` |
| `006770b0` | `006747b0` | `0066f13f` | `00af6ce0` | `006747b0` → `00677a40` → `00678b90` |
| `006770b0` | `006749e0` | `0066f0d5` | `00af6e00` | `006749e0` → `006747b0` → `00677a40` → `00678b90` |
| `006770b0` | `00675040` | `0066f063` | `00af6f20` | `00675040` → `00677d30` → `00678b90` |

Instruction slices show `00676650`, `00677a40`, and `00677d30` passing
`this + 0x74` in `ECX` to `00678b90`. The exported High-P-code for `00678b90`
ends in a tail call to `00486d96`; the captured instruction slice for that
shared block stores `0x00af7394` through the passed member pointer, then jumps
to its common initializer. The intermediate primary-vtable writes to
`00af7150` or `00af7270` occur inside base initialization and are overwritten
by the enclosing constructor with the final primary-vtable values in the table
above.

## Nested call targets

The read-only pointer-table export for `00af7394` gives these exact entries:

| Nested call | Slot | Slot address | Bytes | Static target |
| --- | ---: | --- | --- | --- |
| `00665801` | `+0x8` | `00af739c` | `d0 91 70 00` | `007091d0` |
| `00665841` | `+0xc` | `00af73a0` | `10 72 67 00` | `00677210` |

The nested candidate artifact now includes four additional `00af7394` origins
for each target, one per constructor root above. Its target union is unchanged:
`007091d0` remains a candidate for `00665801`, and `00677210` remains a
candidate for `00665841`. The added origins connect those targets to the
selector-1 `+0x74` path as well as the already retained selector-3/selector-5
paths.

## Limits

The selector remains dynamic, so the replay does not identify the receiver
returned in a particular execution. It covers the four observed constructor
roots used by the cached-field candidate set; it does not exclude other writers
or later mutation. The `/6` memory-effect statuses are unchanged.

## Retained artifacts

- [`field20-field74-00678b90-pcode-flow.tsv`](field20-field74-00678b90-pcode-flow.tsv): 3 rows, including the tail call to `00486d96`.
- [`field20-selector1-instruction-slices.jsonl`](field20-selector1-instruction-slices.jsonl): 9 read-only Ghidra instruction/P-code slices for the constructor paths and shared tail.
- [`field20-field74-vtable-slots.jsonl`](field20-field74-vtable-slots.jsonl): 16 slots from `00af7394`; `+0x8/+0xc` are function entries.
- [`field20-selector1-address-references.jsonl`](field20-selector1-address-references.jsonl): focused xrefs to the getters, wrappers, and two nested-call helpers.
- [`field20-nested-vtable-call-candidates.jsonl`](field20-nested-vtable-call-candidates.jsonl): updated `GhidraIndirectCallVtableCandidates/1` origins.

The P-code, instruction-slice, and pointer-table outputs can be regenerated with
the existing `run_ghidra_function_pcode_flow.sh`,
`run_ghidra_instruction_slices.sh`, and `run_ghidra_pointer_table_slots.sh`
runners against the same saved SHIFT project. Each runner uses read-only,
analysis-disabled Ghidra access.
