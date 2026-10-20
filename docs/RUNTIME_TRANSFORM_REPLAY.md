# Runtime transform replay

`revenginstr-runtime-transform-replay` joins bounded consumer-reported
transform results to exact function-entry events in a pinned
`RuntimeStaticCorrelation/1` report. The manifest pins the correlation report,
the normalized observation rows, the source capture, and the probe script.

Each `RuntimeTransformObservation/1` records a transform candidate, its runtime
function address and source ordinal, input length and key, sample coverage,
sample count, and the consumer's formula result. The replay checks hashes,
field bounds, capture identity, and the exact expected function node. It labels
results `full_match`, `sampled_match`, `observed_mismatch`, or `inconclusive`;
it does not promote any result to an accepted claim.

The consumer computes the formula result while the live buffers exist. The
sample bytes are deliberately omitted, so RevEngInstr cannot recompute that
result. Source and probe hashes identify the artifacts used but do not
authenticate who produced them. A bounded match is evidence for the sampled
positions only; it does not prove whole-buffer behavior or capture completeness.

```sh
revenginstr-runtime-transform-replay \
  runtime-transform-manifest.json runtime-static-correlation.json \
  runtime-transform-observations.jsonl \
  --output runtime-transform-replay.json
```

The consumer-specific Nevergone adapter
[`nevergone_decode_to_runtime_observations.py`](../tools/capture_adapters/nevergone_decode_to_runtime_observations.py)
normalizes Frida Gadget traces without copying buffer bytes or raw pointers
into the observation contract. The retained on-device replay is documented in
[`the Nevergone Decode capture`](evidence/runtime-behavior-replay-v1/nevergone-decode-device-20261020/README.md).
