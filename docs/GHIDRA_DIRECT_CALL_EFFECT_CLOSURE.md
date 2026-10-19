# Direct-call memory-effect closure

`GhidraDirectCallMemoryEffectClosure/1` summarizes each direct call in one
caller P-code flow over the reachable direct-call graph supplied to the
builder. It extends the one-function evidence in
[`GhidraDirectCallMemoryEffect/1`](GHIDRA_FUNCTION_PCODE_FLOW.md) without
changing that format or the existing dominance audit.
The optional static-target join emits
`GhidraDirectCallMemoryEffectClosure/2`; calls without that option continue to
emit `/1`.

## Build a closure

Install the project and run:

```sh
revenginstr-direct-call-memory-effect-closure caller.tsv \
  --program-id sample:program \
  --callee-flow 00402000 callee-00402000.tsv \
  --callee-flow 00403000 callee-00403000.tsv \
  --output call-effect-closure.jsonl
```

Each flow TSV must contain one complete function and use the exact
`GhidraFunctionPcodeFlow/1` header. Supply flows for the transitive direct-call
closure. Unused supplied flows are rejected. Byte, operation, call-site,
function-count, and total closure-visit budgets bound graph traversal and the
reachable-function entries included in output. Repeated calls to the same
direct target reuse the computed summary.

## Join reviewed indirect-target observations

For reviewed `GhidraStaticIndirectCallTarget/1` or
`GhidraIndirectCallVtableCandidates/1` evidence, pass the relevant JSONL file
and the analyzed binary SHA-256:

```sh
revenginstr-direct-call-memory-effect-closure caller.tsv \
  --program-id sample:program \
  --static-indirect-call-targets static-targets.jsonl \
  --program-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --output call-effect-closure.jsonl
```

Pass `--indirect-call-vtable-candidates vtable-candidates.jsonl` for bounded or
partial constructor-derived target sets. Both evidence files can be supplied
to the same invocation.

The join requires an exact `function_entry`, call address, and P-code time, and
rejects evidence for another program identity or binary hash. Matching rows
add source-pinned `indirect_target_observations` under `provenance` in a `/2`
output. Each observation retains its evidence state and scope. These rows
describe the evidence's declared limits; they do not resolve the `CALLIND`,
add a function to its transitive closure, or remove the `indirect_call` effect
barrier. A runtime-mutated pointer can still select a different target.

## Fail-closed statuses

- `no_explicit_memory_write` means every reachable direct callee has a supplied
  flow, and every operation is a known non-writing opcode or a resolved direct
  call whose own closure meets the same rule.
- `explicit_memory_write` means a reachable flow contains `STORE`.
- `unknown_effect` means a reachable flow contains an indirect call, unresolved
  nested call, or opcode outside the known non-writing set.
- An unresolved or missing top-level direct target, and a top-level `CALLIND`,
  retain their distinct statuses.

The walk is cycle-safe. A closed direct-call cycle can be marked write-free
when every function flow is present and the full reachable set contains only
known non-writing operations and resolved direct calls. A missing node or
unknown operation in that cycle leaves the caller call at `unknown_effect`.
`closure_sha256` pins the sorted set of reachable function identities, P-code
flow hashes, and row counts. Consumers should preserve those input TSVs next to
the JSONL output so the result can be replayed.

The existing `FieldStoreLoadDominanceAudit/3` consumes
`GhidraDirectCallMemoryEffect/1`, not this closure format. This builder adds
transitive evidence for review and replay; an audit that consumes it requires a
separately versioned contract. Neither format establishes branch feasibility
or runtime value flow.
