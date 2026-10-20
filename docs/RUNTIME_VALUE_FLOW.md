# Runtime value-flow replay

`revenginstr-runtime-value-flow` replays only candidate pairs named by a
`RuntimeValueFlowManifest/1`. The manifest pins the exact bytes of one
`RuntimeStaticCorrelation/1` report and one JSONL file of
`RuntimeValueObservation/1` rows. Each value row references a correlation
sequence and repeats its runtime address; both selected locations must map to
the candidate's expected static node as one unambiguous exact match.

The first version handles receiver identity, field write/read, state
transitions, factory return/use, call-output/return and allocation/release
pairs. It compares only opaque `hmac-sha256:<hex>` tokens for subject, field
and value slots. Raw values must stay in the consumer. The HMAC shape is a
format check only: the analyzer does not know the secret and cannot verify
token authenticity or stable tokenization. The replay hashes its inputs but
those hashes do not establish who collected them.

`call_output_return` pairs a callee's output-buffer identity with the enclosing
function's returned identity. A witness establishes pointer identity for that
selected pair; it does not establish buffer contents, ownership, lifetime, or
the transform applied to those contents.

Results are `witnessed`, `observed_mismatch` or `inconclusive` for the selected
pair. They do not claim a whole-program path exists or is absent, do not infer
unobserved intermediate events, and never promote a candidate to
`confirmed_exact`. A declared sample gap intersecting a pair, missing pair
observation, address mismatch or non-unique expected static node makes that
pair inconclusive. Partial capture status is retained even when both selected
events are directly observed.

```sh
python -m revenginstr.runtime_value_flow \
  docs/evidence/runtime-value-flow-v1/nevergone-synthetic/manifest.json \
  docs/evidence/runtime-value-flow-v1/nevergone-synthetic/correlation-report.json \
  docs/evidence/runtime-value-flow-v1/nevergone-synthetic/value-observations.jsonl \
  --output /tmp/runtime-value-flow-replay.json
```

This checked-in input is a synthetic contract fixture. The
[Nevergone device replay](evidence/runtime-behavior-replay-v1/nevergone-decode-device-20261020/README.md)
also records 11 `Decode` output-buffer to `getFileData` return identity pairs.
All 11 are witnessed through exact static function matches and operator-keyed
opaque tokens. Capture completeness remains unknown, and the result proves
pointer identity only for those selected calls.
The device pair report replays into 11 `review_required` decision-ledger
events; it does not auto-accept any runtime claim.

## Decision-ledger replay

Convert replay JSON into `AnalysisDecisionLedgerEvent/1` JSONL with:

```sh
python -m revenginstr.runtime_evidence_ledger /tmp/runtime-value-flow-replay.json \
  --output /tmp/runtime-value-flow-ledger.jsonl
```

Each event pins the replay artifact hash and candidate row. A runtime witness
is routed to `review_required`, a pair mismatch to `escalated_conflict`, and an
inconclusive pair to `review_required` with a missing-evidence reason. Every
event has a null confidence delta; this adapter cannot emit `accepted_exact`
or `accepted_high_confidence`.
