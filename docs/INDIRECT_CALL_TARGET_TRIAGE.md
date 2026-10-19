# Indirect-call target triage

`revenginstr-indirect-call-target-triage` condenses the bounded alternatives in
`PointerProvenance/1` `callind_target` rows into one source-pinned row per
`CALLIND`. It distinguishes bounded provenance paths from dynamic call/dispatch
barriers and from analysis limits such as cycles or depth limits. The original
alternatives and their evidence references remain in the output.

```sh
revenginstr-indirect-call-target-triage \
  --program-id sample:program \
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

The report is for acquisition planning. It does not infer target functions,
execute probes, treat candidate paths as a complete target set, or remove the
`CALLIND` effect barrier. Consumer-collected runtime observations must be
separately pinned and joined before a target can be considered observed.
