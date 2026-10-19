# Indirect-call target triage

`revenginstr-indirect-call-target-triage` condenses the bounded alternatives in
`PointerProvenance/1` `callind_target` rows into one source-pinned row per
`CALLIND`. It distinguishes bounded provenance paths from dynamic call/dispatch
barriers and from analysis limits such as cycles or depth limits. The original
alternatives and their evidence references remain in the output. A resolved
constant address-anchor alternative also produces a target-address candidate;
the candidate is bounded only when it covers every retained alternative.
Partial candidates leave uncovered paths visible. The analyzed binary SHA-256
is required and carried into every output row.

```sh
revenginstr-indirect-call-target-triage \
  --program-id sample:program \
  --program-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --pointer-provenance pointer-provenance.jsonl \
  --output callind-target-triage.jsonl
```

`bounded_provenance_only` means every retained alternative has a bounded
structural status (`resolved` or `load_anchor`). A `load_anchor` records where
memory supplied the pointer; it does not establish the value stored there.
`mixed_bounded_and_blocked` retains both a bounded path and a dynamic barrier.
`mixed_bounded_and_unresolved` retains a bounded path alongside an alternative
whose provenance state is neither bounded nor a declared dynamic barrier.
`dynamic_barrier_only` has no bounded path and is blocked by an unresolved call
or indirect dispatch. `analysis_limited` means at least one path hit a declared
provenance limit; its bounded and barrier counts still show any other paths.
`unresolved` covers alternatives that fit none of those cases.

The report is for acquisition planning. A candidate is an address derived
from a resolved constant anchor; it does not verify a function identity,
establish runtime selection, treat uncovered alternatives as resolved, or
remove the `CALLIND` effect barrier. Consumer-collected runtime observations
must be separately pinned before a runtime target can be considered observed.
