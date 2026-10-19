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

The deterministic builder is available as `revenginstr-type-layout-hypothesis`.
It joins `GhidraMemoryStoreAccess/1` rows and optional
`GhidraParameterLoadField/1` TSV rows to exact
[`TypeLayoutMemberMap/1`](../schemas/type-layout-member-map-v1.schema.json)
keys `(function_entry, root_parameter_index)`. The map pins `program_id`, the
binary SHA-256, and an opaque reviewer-chosen `type_id`; the caller supplies the
architecture. The builder emits separate read and write observations, leaves
type candidates, vtable anchors, relationships, and exact object size empty,
and derives a minimum observed extent only from non-negative offsets with
known access widths. Every emitted field and size bound retains its exact
access row and the reviewer map row. Unmatched roots, unresolved store
locations, and negative offsets do not contribute. Parameter loads can be the
only access input when a consumer has no store capture for the selected
members.

For example, the reviewed NFS SHIFT mapping in
[`nfs-shift-member-map.jsonl`](evidence/receiver-field-access/nfs-shift-screening-20261019/scan37/replay-0041dd40/nfs-shift-member-map.jsonl)
projects the constructor, copy, lazy getter, and destructor stores for the
opaque cluster `cluster-vtable-00af0860`. It reproduces the `+0x20` writes,
the exact getter read at `+0x20`, and a 56-byte minimum extent. The referent
type and exact size remain unresolved. The
reproducible builder output is retained
[here](evidence/receiver-field-access/nfs-shift-screening-20261019/scan37/replay-0041dd40/type-layout-builder-output.jsonl).
Run the same projection with:

```sh
revenginstr-type-layout-hypothesis \
  --memory-store-jsonl field20-memory-store-access.jsonl \
  --parameter-loads-tsv field20-parameter-loads.tsv \
  --member-map-jsonl nfs-shift-member-map.jsonl \
  --program-id 'nfs-shift:SHIFT.exe' \
  --program-sha256 eca479aa2d8dbb88bc55709d91ae5c7159ae1b00fc9555d6701000c26de8aee1 \
  --language-id x86:LE:32:default \
  --pointer-width-bytes 4 \
  --addressable-unit-bytes 1 \
  --endianness little \
  --output type-layout-hypothesis.jsonl
```

The builder was also exercised on the consumer-owned Nevergone
[`CCJoyStick::init` memory evidence](https://github.com/Hanz0Hatt0r1/nevergone-recomp/tree/main/docs/evidence/field-store-load-cfg-ccjoystick-init)
with one explicit mapping for function `002a6584`, root parameter 0, and opaque
id `nevergone:opaque-object-002a6584`. The layout output had 13 observed field
offsets from 12 STORE and 9 LOAD sites, with a 337-byte minimum extent. The
binary hash was pinned to
`94b1ef6a9469e261183ac08199c5b0eb65c0c40b81918ca097bd32920828eb5e`.
This is a second-consumer projection smoke, not a verified class layout: exact
size, field types, and class identity remain unknown, and raw Nevergone rows
stay in that consumer repository.
The reviewer-map row used for this smoke was:

```json
{"format":"REVENGINSTR.TypeLayoutMemberMap/1","program_id":"nevergone:libcocos2dcpp.so","program_sha256":"94b1ef6a9469e261183ac08199c5b0eb65c0c40b81918ca097bd32920828eb5e","type_id":"nevergone:opaque-object-002a6584","function_entry":"002a6584","root_parameter_index":0}
```

The synthetic fixture in
`tests/fixtures/type-layout-hypothesis/synthetic.jsonl`
continues to exercise richer candidate fields, a vtable anchor, and an
unresolved composition relationship. These are contract and builder checks,
not a consumer accuracy result; independently reviewed layouts from more than
one consumer remain open.
