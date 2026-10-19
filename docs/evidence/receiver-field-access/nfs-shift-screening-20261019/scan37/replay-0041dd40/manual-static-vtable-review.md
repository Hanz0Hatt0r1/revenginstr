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
