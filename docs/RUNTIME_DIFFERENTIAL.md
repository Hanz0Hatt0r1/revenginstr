# Runtime differential comparison

`revenginstr-runtime-differential` compares two
`RuntimeStaticCorrelation/1` reports. The manifest pins each report by SHA-256
and records one caller-declared input, state, or action change plus the hash of
the context held fixed between runs.

The tool counts `(event_kind, normalized_address)` pairs, reports signatures
whose counts changed, and ranks them by the absolute count difference. It
ignores runtime addresses after normalization, so ASLR differences do not
appear as behavior changes. It does not compare event ordering or sampled
values. Sampling status from both runs remains in the report.

Every ranked result has evidence class `correlation`: the changed observation
coincides with the declared intervention. One pair does not establish a causal
relationship. Repeated, reproducible comparisons are needed for
`intervention_support`; `confirmed_exact` needs stronger exact evidence. This
version emits neither stronger class.

Run the CLI with two correlation reports and a manifest:

```sh
revenginstr-runtime-differential baseline-correlation.json \
  treatment-correlation.json intervention.json \
  --output differential.json
```

The pinned synthetic replay is in
[`docs/evidence/runtime-differential-v1/nevergone-synthetic/`](evidence/runtime-differential-v1/nevergone-synthetic/).
