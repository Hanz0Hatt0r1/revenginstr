# Analysis Decision Ledger

The `AnalysisDecisionLedgerEvent/1` JSONL contract records each subject's
convergence state, previous state, reason codes, responsible actor, confidence
delta, and newly added evidence references. Every event pins the subject kind
and source artifact hash/record. The supported states are
`accepted_exact`, `accepted_high_confidence`, `review_required`,
`escalated_conflict`, `unsupported`, and `budget_exhausted`.

Audit a consumer-owned ledger with:

```sh
revenginstr-decision-ledger-audit decision-events.jsonl \
  --output decision-ledger-audit.json
```

The audit enforces unique event IDs, contiguous per-subject event indexes,
stable subject provenance, and exact agreement between each event's previous
state and the preceding event. It does not impose a state-transition policy.
Its `AnalysisDecisionLedgerAudit/1`
report pins the input hash and emits only aggregate terminal-state, reason, and
transition counts; analysis and subject identifiers are omitted. The
`decision-ledger-audit` stage can be used in pinned benchmark manifests.
