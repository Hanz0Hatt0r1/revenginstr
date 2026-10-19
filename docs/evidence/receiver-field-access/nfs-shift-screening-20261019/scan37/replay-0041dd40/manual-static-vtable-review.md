# Manual static vtable review: `00664a10`

This review uses the pinned retail input `SHIFT.exe` (SHA-256
`eca479aa2d8dbb88bc55709d91ae5c7159ae1b00fc9555d6701000c26de8aee1`) and the
retained High-P-code flow and `CALLIND` rows beside this file. It records a
manual static resolution; it does not change the original
`PointerProvenance/1` output.

## Dispatch to the collection lookup

`FUN_0064a010` initializes the wrapper at `0x00bfa9b0` with the pointer
returned by `FUN_006642a5`. That initializer constructs the global object at
`0x00bfc728` with `FUN_00664140`, whose vtable is `0x00af08a0`. The entry at
vtable byte offset `0x30` is at `0x00af08d0`; its raw value is
`10 4a 66 00`, or target `0x00664a10`. The machine code at `0064a0c0` and
`0064a100` loads slot `+0x30` from that object and calls it at `0064a0ce` and
`0064a10e`, respectively. This pins the two outer dispatches to the
collection lookup for the initialized global object, rather than resolving
arbitrary runtime receiver values.

## Exact initializer body at `006642a5`

The target is the tail-jump destination of thunk `006642a0` (which sets `EAX`
to `1` at `004183cd`). It was missing from the pinned function inventory, so
the retained Ghidra project was copied and this entry was seeded only in that
disposable copy. The exact 43-byte function now has a full 18-operation
High-P-code flow and a CFG/5 export with three blocks and one entry block. See
[`field20-006642a5-replay.md`](field20-006642a5-replay.md),
[`field20-006642a5-pcode-flow.tsv`](field20-006642a5-pcode-flow.tsv), and
[`field20-006642a5-pcode-cfg-v5.jsonl`](field20-006642a5-pcode-cfg-v5.jsonl).

The function checks global initialization guard `0x00bfc818`; its branch
skips the constructor path when the selected bit is already set. Otherwise it
updates the guard, calls `00664140` to initialize global `0x00bfc728`, and
registers callback `0x00a9e620` through `_atexit` (`00900fb3`). Both paths
return the pointer to `0x00bfc728`. The flow contains two direct `CALL`s and
no `CALLIND`; the CFG's two `INDIRECT` P-code markers are linked to those
direct calls. This closes the missing function-flow and CFG acquisition gap,
without identifying the runtime branch taken.

## Receiver population

`00664a10` walks the object collection at `this + 8`. Constructor `00664140`
sets the enclosing object's vtable to `0x00af08a0` and initializes that
collection at `this + 8`. Both direct call sites of the collection append
helper `006641e0` are immediately preceded by factory `0066ee90`:

| Append call | Factory call | Collection argument | Result |
| --- | --- | --- | --- |
| `00665226` | `00665219` | `this + 8` | `0066ee90` instance |
| `006656a8` | `0066569f` | `this + 8` | `0066ee90` instance |

The binary-wide direct-call scan finds these two `CALL` sites for `006641e0`.
Factory `0066ee90` writes vtable address `0x00af0860` to each new object's
first field. Copy helper `00663f50` writes the same vtable address while
copying an existing object. This establishes one observed vtable for the
statically constructed collection members; it does not rule out later runtime
mutation or unobserved insertion paths.

## Slot targets

The PE `.rdata` section maps virtual address `0x00af0860` to file offset
`0x006ef260`. Its 32-bit entries give:

| CALLIND | Vtable slot | Slot address | Slot bytes | Target | Target bytes | Observed operation |
| --- | ---: | --- | --- | --- | --- | --- |
| `00664a4f` (`time=122`) | `0x0` | `0x00af0860` | `00 c7 9e 00` | `0x009ec700` | `8b 41 04 c3` | reads `[this + 4]`, returns |
| `00664a83` (`time=233`) | `0x34` | `0x00af0894` | `80 18 9d 00` | `0x009d1880` | `8b 41 20 c3` | reads `[this + 0x20]`, returns |

Thus both indirect-call target identities are resolved for the observed
collection construction path. The second function returns a field value; its
runtime contents remain unknown. The four downstream anchors in `006657e0`
and `00665820` therefore remain target-unresolved. The existing `/6` pair
statuses are unchanged because this review did not rerun the complete
interprocedural memory-effect audit.

## Exact writers for object offset `+0x20`

The saved Ghidra project for this same binary was opened read-only with
analysis disabled and Java 21. A bounded batch export covers the ten exact
entries in [`field20-functions.txt`](field20-functions.txt): all ten completed
with P-code, yielding 1,527 flow rows. The accompanying
[`GhidraMemoryStoreAccess/1` capture](field20-memory-store-access.jsonl)
contains 58 STORE rows; four are parameter-0-rooted accesses at offset `+0x20`:

| Function | Store address | Source | Observed operation |
| --- | --- | --- | --- |
| `0066ee90` | `0066eee2` | constant zero | Constructor initializes the field to null. |
| `00663f50` | `00663f8d` | load from source object `+0x20` | Copy helper preserves the source field. |
| `0066eff0` | `0066f215` | merged value from five calls or null | Lazy getter checks the cached field; on a miss it branches on the object's type tag, constructs one of the observed variants, then stores the result. |
| `0066ebc0` | `0066ebd2` | constant zero | Releases a non-null cached object through its first virtual method, then clears the field. |

`AptCIH::GetAnimationInst` at `009d1880` is an exact load of `[this + 0x20]`.
The read-only parameter-field exporter also captured this as one
`GhidraParameterLoadField/1` row in
[`field20-parameter-loads.tsv`](field20-parameter-loads.tsv), with root
parameter 0 and width 4. The reviewer membership map joins that getter to the
same opaque cluster as the four exact writers above; the generated type-layout
candidate therefore retains both the getter read and the constructor/copy/
lazy-store/reset writes at `+0x20`.
The [`PointerProvenance/1` replay](field20-pointer-provenance.jsonl) keeps the
value reaching `0066f215` ambiguous: five call-result barriers and two null
alternatives. The candidate field therefore has observed initialization,
copy, lazy materialization, and reset paths, while the actual runtime
referent/type on the four downstream callsites remains unresolved.

[`TypeLayoutHypothesis/1`](field20-type-layout-hypothesis.jsonl) records this
as an opaque review-level cluster anchored at `0x00af0860`. It contains a
56-byte minimum observed extent and a 4-byte data-pointer candidate at `+0x20`;
exact size, pointee identity, and inheritance/composition links remain unset.

The flow, indirect-call, acquisition, memory-access, and parameter-store
captures are retained beside this review and pinned by the parent manifest.
Their hashes bind each derived pointer-provenance alternative back to the
P-code rows. This narrows the static writer gap; it does not promote the four
`/6` rows or identify a target class.

## Bounded first-level vtable targets

The retained P-code now links each of the five constructor call results in
`0066eff0` to the `+0x20` store at `0066f215`. The six-row
[`field20-call-store-flow.jsonl`](field20-call-store-flow.jsonl) capture records
those result-to-store paths, including the null alternative. Joining those
paths to the constructor vtable writes and the pinned executable's raw table
bytes yields a bounded candidate set for the two first-level calls whose
receiver is the cached field:

| CALLIND | Slot | Candidate target | Observed vtable origin(s) |
| --- | ---: | --- | --- |
| `006657ed` | `+0x30` | `00663030` | `00af6bf0` |
| `006657ed` | `+0x30` | `00676040` | `00af6a50` |
| `006657ed` | `+0x30` | `006770b0` | `00af6ce0`, `00af6e00`, `00af6f20` |
| `0066582d` | `+0x34` | `00663030` | `00af6bf0` |
| `0066582d` | `+0x34` | `00676040` | `00af6a50` |
| `0066582d` | `+0x34` | `006770b0` | `00af6ce0`, `00af6e00`, `00af6f20` |

The candidate set covers the five concrete vtable values observed in this
lazy-construction flow. It does not show which type-tag branch executes at
runtime, exclude unobserved writers, or establish a unique runtime target.
The raw slot values and file offsets, factory calls, constructor-return
proofs, and `+0x20` store-graph references are retained per origin in
[`field20-vtable-call-candidates.jsonl`](field20-vtable-call-candidates.jsonl)
using [`GhidraIndirectCallVtableCandidates/1`](../../../../../../schemas/ghidra-indirect-call-vtable-candidates-v1.schema.json).

The later calls `00665801` (`+0x8`) and `00665841` (`+0xc`) use the prior
`CALLIND` results as receivers. A follow-up replay traces subobject vtables
written by the observed first-level constructors, giving partial static target
sets for both calls. In particular, the original cached object's vtable
entries at `+0x8` and `+0xc` are not evidence for these calls.

## Partial targets on returned subobjects

Read-only P-code batches completed for all eight constructor/helper functions
and all six getter/leaf functions. The inputs, outputs, and acquisition rows
are retained in [`field20-subobject-constructor-functions.txt`](field20-subobject-constructor-functions.txt),
[`field20-subobject-constructor-pcode-flow.tsv`](field20-subobject-constructor-pcode-flow.tsv),
[`field20-subobject-constructor-callind.jsonl`](field20-subobject-constructor-callind.jsonl),
[`field20-subobject-constructor-acquisition.jsonl`](field20-subobject-constructor-acquisition.jsonl),
[`field20-subobject-dispatch-functions.txt`](field20-subobject-dispatch-functions.txt),
[`field20-subobject-dispatch-pcode-flow.tsv`](field20-subobject-dispatch-pcode-flow.tsv),
[`field20-subobject-dispatch-callind.jsonl`](field20-subobject-dispatch-callind.jsonl),
and [`field20-subobject-dispatch-acquisition.jsonl`](field20-subobject-dispatch-acquisition.jsonl).
All 14 functions completed with P-code; the constructor replay contains 2,402
flow rows and the getter/leaf replay contains 56. The getter case mapping is
preserved with the source hash in
[`field20-subobject-dispatch-cases.md`](field20-subobject-dispatch-cases.md).

The returned-object getters expose these static cases:

| Getter target | Selector | Returned member | Bounds |
| --- | ---: | --- | --- |
| `00676040` | 4 | parent `+0x128` | index `< 3`, stride `0x5c` |
| `006770b0` | 2 | parent `+0x4c0` | index `< 2`, stride `0x48` |
| `006770b0` | 4 | parent `+0x128` | index `< 10`, stride `0x5c` |
| `006770b0` | 5 | parent `+0x550` | singleton |

The existing first-level rows do not bind the runtime selector register. The
known getters at `00676040` and `006770b0` also return parent `+0x74` for
selector 1; that member's vtable is still unresolved. A separate selector-3
path through `00663030` returns parent `+0x7c`. Base constructor `006634a0`
writes vtable `00af0628` there. The exact getter instructions are retained in
[`field20-63030-selector-disassembly.md`](field20-63030-selector-disassembly.md);
they do not prove selector 3 is supplied at runtime.

The bounded constructor replay also shows `006634a0` storing zero to its own
`this + 0x74` at `006634cd` (P-code flow rows 13–14 in
[`field20-base-subobject-init-pcode-flow.tsv`](field20-base-subobject-init-pcode-flow.tsv)).
That is a null initialization in this constructor, not a vtable for the
selector-1 results of `00676040` or `006770b0`; later writers and those results
remain unresolved.

The constructor helpers write vtables `00af6b38` at `+0x128`, `00af7050` at
`+0x4c0`, and `00af723c` at `+0x550`. The getter conditions above therefore
bound the following partial candidates from the pinned executable's raw slot
bytes:

| Later `CALLIND` | Slot on returned object | Static target | Returned-object vtable origins | Origin paths |
| --- | ---: | --- | --- | ---: |
| `00665801` | `+0x8` | `00674f10` | `00af6b38`, `00af7050` | 7 |
| `00665801` | `+0x8` | `007091d0` | `00af723c` | 3 |
| `00665841` | `+0xc` | `00674f30` | `00af6b38`, `00af7050` | 7 |
| `00665841` | `+0xc` | `00677210` | `00af723c` | 3 |

The PE `.rdata` mapping used for these slots has virtual base `00aa6000` and
raw file offset `006a4a00`. The six little-endian entries are:

| Vtable | Slot | File offset | Bytes | Target |
| --- | ---: | --- | --- | --- |
| `00af6b38` | `+0x8` | `006f5540` | `10 4f 67 00` | `00674f10` |
| `00af6b38` | `+0xc` | `006f5544` | `30 4f 67 00` | `00674f30` |
| `00af7050` | `+0x8` | `006f5a58` | `10 4f 67 00` | `00674f10` |
| `00af7050` | `+0xc` | `006f5a5c` | `30 4f 67 00` | `00674f30` |
| `00af723c` | `+0x8` | `006f5c44` | `d0 91 70 00` | `007091d0` |
| `00af723c` | `+0xc` | `006f5c48` | `10 72 67 00` | `00677210` |
| `00af0628` | `+0x8` | `006ef030` | `d0 91 70 00` | `007091d0` |
| `00af0628` | `+0xc` | `006ef034` | `10 72 67 00` | `00677210` |

The seven paths for the first two vtables retain each applicable parent
constructor, including `006749e0` calling base constructor `006747b0`; the
three `00af723c` paths are the applicable `006747b0`, `006749e0`, and
`00675040` constructor roots. The `00af0628` origin adds the `00673150` parent
constructor path through `006634a0`. Each vtable origin in
[`field20-nested-vtable-call-candidates.jsonl`](field20-nested-vtable-call-candidates.jsonl)
links back to its first-level candidate row, the selector case, the
constructor call path, the exact helper STORE/PTRSUB rows, and the raw slot
address and bytes. The schema labels these rows
`partial_static_target_candidates` because runtime selector values, the
selector-1 `+0x74` member, and unobserved writers remain unresolved.

The new generic [`IndirectCallPointerSlot/1` replay](indirect-call-pointer-slots.jsonl)
joins all 22 closure targets to their exact `PointerProvenance/1` rows. It
reports six aligned constant-offset pointer-slot candidates. For the four
downstream sites it records `006657ed` at `+0x30`, `00665801` at `+0x8`,
`0066582d` at `+0x34`, and `00665841` at `+0xc`. These are slot-access
shapes rooted at runtime memory-read anchors; none identifies a table or
target function.

The read-only xref export is retained in
[`anchor-address-references.jsonl`](anchor-address-references.jsonl). It
records direct callers of the two wrappers and every reference to the
`0x00af0860` and `0x00af08a0` table addresses. `0043c792` is entered by the
cleanup path `0066efc0`; it is a vtable reset in that path, not an additional
factory. These xrefs still do not recover the runtime value stored at object
offset `+0x20`.

## Reproduction

With the pinned executable available as `SHIFT.exe`, the two direct append
calls are reproduced with:

```sh
objdump -d -Mintel SHIFT.exe | rg 'call\s+0x6641e0\b'
```

It prints call sites `0x00665226` and `0x006656a8`. For the vtable bytes,
`.rdata` has virtual base `0x00aa6000` and raw offset `0x006a4a00`, so
`0x00af0860` maps to file offset
`0x006a4a00 + (0x00af0860 - 0x00aa6000) = 0x006ef260`. Inspect the two
entries and their leaf targets with:

```sh
xxd -g1 -s 0x6ef260 -l 0x38 SHIFT.exe
objdump -d -Mintel --start-address=0x009ec700 --stop-address=0x009ec704 SHIFT.exe
objdump -d -Mintel --start-address=0x009d1880 --stop-address=0x009d1884 SHIFT.exe
```

The entry at table offset `0` is at raw offset `0x006ef260`; the entry at
table offset `0x34` is at raw offset `0x006ef294`.

The read-only generic Ghidra exporter also captured 16 slots from each table
in [`ghidra-pointer-table-slots.jsonl`](ghidra-pointer-table-slots.jsonl).
Its rows for `0x00af08a0 + 0x30`, `0x00af0860 + 0`, and
`0x00af0860 + 0x34` report the same targets and raw values. This is slot
inventory evidence; it does not associate arbitrary receiver values with
either table.

The containing controller's slot `+0x30` is reproducible with:

```sh
xxd -g1 -s 0x6ef2d0 -l 4 SHIFT.exe
objdump -d -Mintel --start-address=0x0064a0c0 --stop-address=0x0064a115 SHIFT.exe
```

The existing local Ghidra C export used to cross-check constructor and method
relationships had SHA-256
`512753a5f91898885263c91664a3d3fa3e07bfd58b72d3a5f89c402a00760ee9`; it is
not copied into this evidence bundle. Target bytes and slot values above are
reproducible directly from the pinned executable.

Rebuild the bounded pointer-slot projection from the retained target and
provenance inputs with:

```sh
revenginstr-indirect-call-pointer-slots \
  --program-id 'nfs-shift:SHIFT.exe' \
  --pointer-provenance closure-pointer-provenance.jsonl \
  --indirect-call-evidence closure-callind.jsonl \
  --output /tmp/indirect-call-pointer-slots.jsonl
```

The raw address-reference rows were exported read-only from the existing
analyzed Ghidra project with:

```sh
GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_address_references.sh \
  /path/to/ghidra-projects shift SHIFT.exe /tmp/anchor-address-references.jsonl \
  0x006657e0 0x00665820 0x00665880 0x0066ee90 0x00663f50 \
  0x009d1880 0x00af0860 0x00af08a0 0x0043c792 0x0066efc0 0x0066efcd
```

The returned-subobject P-code replays use the saved `shift` project with
analysis disabled. From the repository root, reproduce both batches with:

```sh
GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_pcode_flow_batch.sh \
  /home/pes/ghidra_projects/shift shift SHIFT.exe \
  docs/evidence/receiver-field-access/nfs-shift-screening-20261019/scan37/replay-0041dd40/field20-subobject-constructor-functions.txt \
  docs/evidence/receiver-field-access/nfs-shift-screening-20261019/scan37/replay-0041dd40/field20-subobject-constructor-pcode-flow.tsv \
  docs/evidence/receiver-field-access/nfs-shift-screening-20261019/scan37/replay-0041dd40/field20-subobject-constructor-callind.jsonl \
  docs/evidence/receiver-field-access/nfs-shift-screening-20261019/scan37/replay-0041dd40/field20-subobject-constructor-acquisition.jsonl \
  8 900 > docs/evidence/receiver-field-access/nfs-shift-screening-20261019/scan37/replay-0041dd40/field20-subobject-constructor-export.log 2>&1

GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_pcode_flow_batch.sh \
  /home/pes/ghidra_projects/shift shift SHIFT.exe \
  docs/evidence/receiver-field-access/nfs-shift-screening-20261019/scan37/replay-0041dd40/field20-subobject-dispatch-functions.txt \
  docs/evidence/receiver-field-access/nfs-shift-screening-20261019/scan37/replay-0041dd40/field20-subobject-dispatch-pcode-flow.tsv \
  docs/evidence/receiver-field-access/nfs-shift-screening-20261019/scan37/replay-0041dd40/field20-subobject-dispatch-callind.jsonl \
  docs/evidence/receiver-field-access/nfs-shift-screening-20261019/scan37/replay-0041dd40/field20-subobject-dispatch-acquisition.jsonl \
  6 900 > docs/evidence/receiver-field-access/nfs-shift-screening-20261019/scan37/replay-0041dd40/field20-subobject-dispatch-export.log 2>&1
```
