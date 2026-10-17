# Direct-call memory-effect closure

`GhidraDirectCallMemoryEffectClosure/1` summarizes each direct call in one
caller P-code flow over the reachable direct-call graph supplied to the
builder. It extends the one-function evidence in
[`GhidraDirectCallMemoryEffect/1`](GHIDRA_FUNCTION_PCODE_FLOW.md) without
changing that format or the existing dominance audit.

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
