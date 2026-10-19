# Indirect call pointer-slot candidates

`IndirectCallPointerSlot/1` joins exact
`GhidraIndirectCallEvidence/1`, `/2`, or `/3` targets to their
`PointerProvenance/1` load definitions. It emits a `slot_access_candidate`
only when the target is loaded from one resolved memory/address anchor plus a
constant byte offset, and the offset is aligned to the pointer width. Signed
offsets are preserved for address-point tables.

The output records the exact call site, bounded target expression, base anchor,
slot offset, pointer width, and hashes/row ordinals for both joins. Conflicting
target tokens or mismatched source hashes fail closed. Missing or ambiguous
provenance becomes an explicit non-candidate status.

This structural shape does not establish a vtable, object class, receiver
identity, ABI convention, or function target. A consumer can use the slot
offset to select a bounded pointer-table query, then join the table to a
receiver only when separate evidence supports that relationship.

```sh
revenginstr-indirect-call-pointer-slots \
  --program-id 'consumer:analysis-id' \
  --pointer-provenance pointer-provenance.jsonl \
  --indirect-call-evidence callind.jsonl \
  --output indirect-call-pointer-slots.jsonl
```

Repeat both input options for additional shards from the same program. The
program id must match every pointer-provenance row. Output is sorted by
normalized function entry, call address, and call time. Each combined input
family is bounded by `--max-rows` (one million rows by default).
