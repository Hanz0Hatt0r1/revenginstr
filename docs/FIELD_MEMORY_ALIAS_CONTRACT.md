# Field memory alias contract (M2.3)

This is the implementation boundary for extending the CFG dominance audit into
memory reaching definitions. The existing `FieldStoreLoadDominanceAudit/1`
remains a structural CFG candidate; this contract does not upgrade existing
rows into value-flow evidence.

## What a memory-access fact must identify

Every represented `LOAD` or `STORE` must be joinable to exactly one operation
using all of:

- opaque `program_id`;
- `function_entry`;
- P-code operation `address` and `time`;
- opcode (`LOAD` or `STORE`);
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
point to distinct objects. Dynamic indices, unsupported arithmetic, pointer
wrap, missing derivation operations, or incomplete widths make the location
unresolved.

## Conservative comparison rules

1. Exact operation-key mismatches are errors; they never fall back to matching
   by address alone.
2. A store in a known different logical P-code space is outside the tracked
   logical-space effect set used by the current CFG audit. This is not a claim
   about physical overlays or runtime mappings.
3. For same-space writes, a non-alias result requires the same proven base
   root, compatible address arithmetic with no pointer wrap, known access and
   pointer widths, and non-overlapping half-open byte intervals. Equal offsets,
   partial overlap, distinct or unknown roots, and unknown widths remain
   possible effects.
4. A `STORE` without a complete matching location fact remains a possible
   effect, even if other stores in the function were resolved.
5. Calls, `CALLIND`, `CALLOTHER`, `INDIRECT`, `UNIMPLEMENTED`, and unclassified
   operations remain barriers unless a separately versioned and validated
   effect summary says otherwise.
6. Branch feasibility and runtime path/value claims remain out of scope.

## Required validation before enabling the filter

The generic tests must cover disjoint, equal, and partially overlapping ranges;
different and unknown roots; unknown widths; dynamic/wrapping offsets; missing
and duplicate operation facts; a resolved store alongside an unresolved
intervening store; and logical spaces that share a physical-space identity.
Every result must retain hashes and record identities for the pair graph, CFG,
and access facts. The consumer workflow must freeze its own access facts and
expected outputs; labels, addresses, raw rows, and measured outcomes stay in
that consumer repository.

Do not extend `FieldStoreLoadDominanceAudit/1` in place for these facts. Add a
versioned output contract with the third input hash and preserve the current
CFG/1/CFG/2 behavior for existing consumers.
