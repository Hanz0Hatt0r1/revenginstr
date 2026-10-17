# Function Summary

`revenginstr-structured-summary` groups equivalent facts from a
`REVENGINSTR.FunctionEffectIR/1` JSONL file into a compact
`REVENGINSTR.FunctionSummary/1` artifact:

```sh
revenginstr-structured-summary function-effects.jsonl \
  --output function-summaries.jsonl
```

Each claim retains its evidence class, structural attributes, supporting
effect IDs, and original artifact SHA-256/record ordinals. The output also
pins the exact Effect IR file hash. Ordering is deterministic; identical
claims are coalesced while retaining every support reference.

This is a structural projection only. It does not assign semantic roles,
natural-language descriptions, or store-to-load reachability. A renderer may
only restate claims and evidence present in this artifact. The
`structured-summary` stage is available to pinned benchmark manifests.
