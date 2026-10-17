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

When the input uses `FunctionEffectIR/2`, the same command emits
`FunctionSummary/2`. It groups generic `memory_read` and `memory_write` effects
by kind and retains every source effect id and provenance reference. The
summary pins the complete Effect IR file hash, so original operand tokens and
read output tokens remain recoverable from that artifact without copying
operation-specific values into the compact claim. A v1 input still produces
the unchanged v1 summary.

This is a structural projection only. It does not assign semantic roles,
natural-language descriptions, or store-to-load reachability. A renderer may
only restate claims and evidence present in this artifact. The
`structured-summary` stage is available to pinned benchmark manifests.
