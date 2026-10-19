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

The builder accepts optional reviewer-supplied
[`TypeLayoutSizeReview/1`](../schemas/type-layout-size-review-v1.schema.json)
rows through `--size-review-jsonl`. Each row pins the type and program, exact
size, source hash, source record, and evidence class. The builder attaches that
evidence without deriving a size from the observed extent; a size below the
extent or conflicting exact-size reviews makes the hypothesis `conflicted`.

The builder also accepts reviewer-supplied
[`TypeLayoutFieldTypeReview/1`](../schemas/type-layout-field-type-review-v1.schema.json)
rows through `--field-type-review-jsonl`. A row joins only by pinned
`(program_id, program_sha256, type_id, offset_bytes)` and can carry a type kind,
width, and optional pointer target. Its offset must already have an observed
field. Competing candidates remain on that field and mark it conflicted; the
review never fills gaps or infers neighboring fields.

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
type candidates, vtable anchors, and relationships empty unless a matching
field-type review is supplied, and derives a minimum observed extent only from
non-negative offsets with known access widths. Exact size remains null unless a
matching size-review row is supplied. Every emitted field and size bound
retains its exact access row and the reviewer map row.
Unmatched roots, unresolved store
locations, and negative offsets do not contribute. Parameter loads can be the
only access input when a consumer has no store capture for the selected
members.

For example, the reviewed NFS SHIFT mapping in
[`nfs-shift-member-map.jsonl`](evidence/receiver-field-access/nfs-shift-screening-20261019/scan37/replay-0041dd40/nfs-shift-member-map.jsonl)
projects the constructor, copy, lazy getter, and destructor stores for the
opaque cluster `cluster-vtable-00af0860`. It reproduces the `+0x20` writes,
the exact getter read at `+0x20`, one four-byte `data_pointer` candidate, the
`0x00af0860` vtable anchor, and a 56-byte minimum extent. The pointer referent
and exact object size remain unresolved. The
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
id `nevergone:opaque-object-002a6584`. The layout output has 13 observed field
offsets from 12 STORE and 9 LOAD sites, with a 337-byte minimum extent. A
separate reviewer size record captures the exact `0x154` allocation request
in the symbolized `CCJoyStick::create` function and its subsequent constructor
call. The reviewed output reports a 340-byte exact size, supported by the
hash-pinned instruction excerpt in
[`allocation-sequence.txt`](evidence/type-layout-review/nevergone-ccjoystick-20261019/allocation-sequence.txt).
The binary hash is
`94b1ef6a9469e261183ac08199c5b0eb65c0c40b81918ca097bd32920828eb5e`.
The new field-type review records `data_pointer` candidates, width 4, targeting
`cocos2d::CCSprite` at `+0x104`, `+0x108`, and `+0x10c`, two integer candidates
copied from the `int` parameters, and four boolean candidates copied from the
`bool` parameters of `CCJoyStick::init`. Other field types, vtable anchors, and
class identity of the containing object remain unresolved. Raw Nevergone
store/load rows stay in that consumer repository. The complete review bundle is retained in
[`nevergone-ccjoystick-20261019`](evidence/type-layout-review/nevergone-ccjoystick-20261019/README.md).
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
