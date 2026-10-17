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
   opcodes, and missing callee flows stay barriers. `/4` consumes the separate
   `GhidraDirectCallMemoryEffectClosure/1` sidecar and removes a call only when
   its hash-pinned transitive closure is complete and write-free; unresolved,
   indirect, unknown, and STORE effects remain barriers.
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
budget, schema, and audit-join cases. NFS Shift PRs [#2025](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2025)
and [#2026](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2026)
freeze 28 exact pairs across ten functions; no complete write-free callee was
present in that subset. The expanded consumer replay in [PR
#2027](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2027)
covers 31 pairs across twelve functions. One complete write-free direct call
joins to an exact CFG witness; an `unknown_effect` direct call also lies on
that witness, so `/3` leaves the pair unresolved. This exercises
the on-path filter boundary without a status promotion or value-flow claim.
NFS PR [#2028](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2028)
extends the frozen consumer replay to thirteen functions and 33 pairs. It has
two complete write-free calls on each of two witnesses, with indirect calls
still present on both paths; neither pair is promoted. NFS PR
[#2029](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2029)
records a screen of 22 functions with zero `ParameterStoreField/1` rows and
zero field pairs; its general STORE sidecar contains 156 facts, 53 with a
parameter root. PR [#2030](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2030)
adds scan15: 62 functions, zero parameter field-store rows, 238 parameter loads,
and 302 general STORE facts. PR [#2031](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2031)
adds scan16: 70 functions, 18 parameter field-store rows, and five exact pairs
across three functions. Its `/3` audit reports three possible intervening
effects and two stores that do not dominate the load. PR [#2032](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2032)
freezes the matching `/2` audit; all five statuses match `/3`, with zero
status changes or unique candidates. NFS PR
[#2033](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2033)
freezes scan17 over 49 functions with exactly two indirect calls: 17
parameter-field stores form 72 exact pairs across 15 roots. All 72 `/2` and
`/3` statuses match (70 stores do not dominate the load; two possible
intervening effects), with no unique candidate. Its call sidecar has 73
explicit-write sites, 30 indirect-call barriers, and no complete write-free
direct callee. Labels, addresses, raw rows, and measured outcomes stay in the
consumer repository.

NFS PR [#2034](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2034)
freezes scan18 over 24 functions with exactly three indirect calls: nine
parameter-field stores form five pairs across three roots. `/2` and `/3` agree
on three non-dominating stores and two possible intervening effects, with no
unique candidate. PR [#2035](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2035)
freezes scan19 over two functions with exactly four indirect calls; PR
[#2036](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2036)
freezes scan20 over eight functions with exactly five indirect calls. Both
screens have no parameter-field stores or pairs: scan19 retains 18 parameter
loads and nine general STORE facts, while scan20 retains 79 loads and 42 STORE
facts. NFS PR [#2037](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2037)
freezes scan21 over three functions with exactly six indirect calls, 28 loads,
and 12 STORE facts, with no field stores or pairs. PR
[#2038](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2038)
freezes scan22 over one function with exactly nine indirect calls and two
parameter-field pairs; both remain `store_not_dominating_load` in `/2` and `/3`.
It retains 12 loads and three STORE facts. PR
[#2039](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2039)
freezes scan23 over the final eligible function with exactly ten indirect
calls, five loads, and four STORE facts, but no field stores or pairs. No
dominance audit was run for scans19–21 or 23; the 1,000-row sample has no more
eligible roots under these filters.

The generic transitive call-effect builder is merged in
[revenginstr PR #108](https://github.com/Hanz0Hatt0r1/revenginstr/pull/108).
The versioned `/4` consumer keeps `/1`–`/3` unchanged and records the closure
sidecar hash plus exact call-site ordinals. Synthetic tests cover write-free,
explicit-write, unknown, missing-flow, indirect, and unresolved statuses;
consumer replay remains the next validation step.

`FieldStoreLoadDominanceAudit/1` is not extended in place. With no sidecars the
command preserves `/1`; supplying only access facts selects `/2`; supplying
access facts and direct-call effects selects `/3`; supplying access facts and
transitive closure rows selects `/4`. The `/3` and `/4` versions record their
respective call-sidecar hashes and exact row ordinals.
