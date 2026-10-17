# Field memory alias contract (M2.3)

This defines the evidence boundary for the versioned
`FieldStoreLoadDominanceAudit/2` and `/3`. The existing `/1` and `/2` outputs
remain unchanged when the corresponding optional sidecars are absent; none of
the versions is runtime value-flow evidence.

## What a memory-access fact must identify

The current sidecar represents every `STORE`; each row must join to exactly
one CFG operation using all of:

- opaque `program_id`;
- `function_entry`;
- P-code operation `address` and `time`;
- opcode (`STORE` in this sidecar; the paired `LOAD` remains identified by the
  field-access graph and CFG);
- logical P-code address-space identity;
- physical address-space identity and pointer width in bytes when the exporter
  can resolve them;
- access width in bytes.

Address-space names provide the logical P-code context. Ghidra also exposes a
physical space for an address space; a logical-space difference alone must not
be used to claim that physical or runtime mappings cannot overlap. See the
[P-code address-space model](https://ghidra.re/ghidra_docs/languages/html/pcoderef.html#address-space)
and [`AddressSpace.getPhysicalSpace()`](https://ghidra.re/ghidra_docs/api/ghidra/program/model/address/AddressSpace.html#getPhysicalSpace()).

To classify same-space writes, a fact must additionally provide either:

- a fully resolved location: a stable base-root identity, signed byte offset,
  positive access width, pointer width, and the operation IDs that justify the
  root and offset; or
- an explicit unresolved state, which remains a possible aliasing effect.

The root identity is scoped to the exact program and function. A formal
parameter index is a valid root only when the derivation shows that the access
address comes from that parameter. Distinct parameters are not assumed to
point to distinct objects. Dynamic indices, unsupported arithmetic, missing
derivation operations, or incomplete widths make the location unresolved.

## Conservative comparison rules

1. Exact operation-key mismatches are errors; they never fall back to matching
   by address alone.
2. The legacy `/1` audit retains its CFG/2 logical-space rule for compatibility;
   that rule is not a claim about physical overlays or runtime mappings. The
   `/2` sidecar path excludes a store only for known different physical spaces
   or a proven same-root disjoint range.
3. For same-space writes, a non-alias result requires the same proven base
   root, compatible address arithmetic, known access and pointer widths, and
   non-overlapping half-open byte intervals. The implementation compares
   circular byte intervals only when the address-space byte modulus exactly
   matches the pointer modulus and both widths are smaller than that modulus;
   otherwise it fails closed. Equal offsets, partial overlap, distinct or
   unknown roots, and unknown widths remain possible effects.
4. A `STORE` without a complete matching location fact remains a possible
   effect, even if other stores in the function were resolved.
5. In `/1` and `/2`, calls, `CALLIND`, `CALLOTHER`, `INDIRECT`, `UNIMPLEMENTED`,
   and unclassified operations remain barriers. `/3` removes only an exact
   `CALL` barrier with a `GhidraDirectCallMemoryEffect/1` row backed by a
   non-empty one-function callee flow containing only known write-free P-code
   operations. The builder does not recurse: nested calls, `CALLIND`, unknown
   opcodes, and missing callee flows stay barriers.
6. Branch feasibility and runtime path/value claims remain out of scope.

## Implemented generic boundary and remaining validation

`GhidraMemoryStoreAccess/1` and the versioned `/2` audit implement exact
operation joins, unresolved rows, physical-space separation, same-root range
comparison, comparison budgets, and provenance for all three inputs. Generic
tests cover overlap, different roots, unresolved locations, unknown widths,
missing candidates, orphan/mismatched rows, physical/logical space
distinctions, pointer-ring ranges, duplicate facts, and budget exhaustion.
The first consumer-owned `/2` replay is frozen in Nevergone PR #729; its two
rows remain possible intervening effects.

`GhidraDirectCallMemoryEffect/1` and `/3` add exact direct-call site facts from
the caller and callee P-code flow hashes. A call is exempted only if its entire
one-function flow uses a known write-free opcode set; this is a narrow
structural result and does not recurse across calls. Synthetic tests cover the
write-free, explicit-store, nested/unknown, missing-summary, indirect-call,
budget, schema, and audit-join cases. NFS Shift's second consumer-owned frozen
`/3` replay is recorded in [PR #2025](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2025):
16 exact pairs replay across five functions with the same status counts in
`/1`, `/2`, and `/3`; all remain unresolved, and no complete write-free callee
was present to exercise a positive filter. This confirms fail-closed behavior
in a second consumer but does not establish value flow or consumer-level
positive filtering. Labels, addresses, raw rows, and measured outcomes stay in
their consumer repository.

`FieldStoreLoadDominanceAudit/1` is not extended in place. With no sidecars the
command preserves `/1`; supplying only access facts selects `/2`; supplying
access facts and direct-call effects selects `/3`, which records both sidecar
hashes and their row ordinals.
