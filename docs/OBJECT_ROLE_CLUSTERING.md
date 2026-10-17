# Object-role structural clusters

`revenginstr-object-role-clusters` compares caller-normalized function feature
sets and emits hash-pinned similarity candidates. The feature groups are
`receiver`, `field`, `vtable_slot`, `callgraph`, and `effect_ir`. Each feature
is an opaque SHA-256 value with source format, artifact hash, and source record
index; raw labels and feature values are not copied into the report.

Generate a feature set from the shared evidence contracts:

```sh
revenginstr-object-role-features function-effects.jsonl \
  --receiver-inference receiver-inference.jsonl \
  --vtable-slots-tsv vtable-slots.tsv.gz \
  --callgraph-metrics callgraph-metrics.jsonl \
  --output object-role-features.jsonl
```

`FunctionEffectIR/1` is required; the receiver, vtable-slot, and callgraph
inputs are optional. The command writes a companion
`object-role-features.jsonl.manifest.json` using
[`ObjectRoleFeatureExtractionManifest/1`](../schemas/object-role-feature-extraction-manifest-v1.schema.json),
pinning every supplied input and row count. All inputs must come from the same
program. Receiver-inference and vtable-slot formats do not carry a program id,
so selecting same-program inputs is the caller's responsibility. The extractor
uses field parameter/offset/width, effect kind, direct
call neighbors, bucketed fan-in/fan-out, uniquely resolved receiver vtable
ids, and vtable slot offsets. It does not use class names or function names.

Adapters should hash a group-scoped canonical value as:

```text
SHA256(UTF8(group + "\0" + canonical_value))
```

Write one [`ObjectRoleFeatureSet/1`](../schemas/object-role-feature-set-v1.schema.json)
JSONL row per function. Features in a row must be unique by group and hash;
when several source records support the same feature, retain each source in
the feature's `support` array. `program_id` scopes function identities and
feature comparisons. The extractor applies this normalization and preserves
the original artifact provenance for every emitted feature.

```sh
revenginstr-object-role-clusters object-role-features.jsonl \
  --threshold 0.5 --min-shared-groups 2 \
  --output object-role-clusters.json
```

For each pair sharing at least the requested number of feature groups, the
tool averages Jaccard similarity across groups present on both sides. Pairs
that pass the threshold form connected components. The report retains each
accepted pair and its shared feature hashes so consumers can join them back to
the pinned feature set.

[`ObjectRoleClusterAudit/1`](../schemas/object-role-cluster-audit-v1.schema.json)
contains structural similarity only. Thresholds are caller-selected and are
not calibrated confidence. A connected component is not a semantic role,
class, inheritance, or object-identity claim; the transitive links do not
guarantee that every pair of members is similar. Consumer feature adapters
and family-isolated evaluation remain open roadmap work.
