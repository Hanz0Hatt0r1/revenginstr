# Type layout hypotheses

`TypeLayoutHypothesis/1` is a JSONL record for one consumer-selected object or
type cluster. It is a storage contract for evidence-backed candidates, not a
layout inference algorithm. `program_id` and `type_id` are opaque joins; the
program hash and architecture identify the binary context.

The object-size fields separate a lower bound from an exact size. An observed
access at offset `N` with width `W` can support a minimum extent of `N + W`,
but does not establish the allocation size. Exact size requires its own source
evidence. If the exact size is smaller than the observed lower bound, preserve
the conflicting evidence and report `size_bound_conflict` instead of silently
choosing one value. Each field retains individual read, write, or address observations;
each candidate field type and vtable anchor also carries its own evidence.

`candidate`, `review`, and `conflicted` are triage states, not confidence
scores. A conflicted record, field, or relationship must retain at least one
reason-coded conflict. The schema does not rank competing types, infer field
names, or promote a vtable anchor to class identity. Addresses are only
meaningful in the pinned program context. Overlapping field candidates are
allowed so ambiguity remains representable.

The synthetic fixture in `tests/fixtures/type-layout-hypothesis/synthetic.jsonl`
exercises a bounded size claim, a pointer-width field candidate, a vtable
anchor, and an unresolved composition relationship. It is contract coverage,
not a consumer accuracy result. The next implementation step is a deterministic
builder from hash-pinned memory-access and type/vtable evidence, followed by
independently reviewed layouts from more than one consumer.
