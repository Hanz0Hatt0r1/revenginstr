# Runtime probe evaluation

`revenginstr-runtime-probe-evaluate` summarizes outcomes for the exact
`consumer_native_probe` requests selected by an `EvidenceRequestPlan/1`. The
manifest maps every request to its pre-run static prediction, baseline
uncertainty and material-narrowing threshold. A JSONL receipt is required for
each selected request, including incomplete probes. Plan and receipt bytes are
hash-pinned; actual steps and elapsed time must stay within each planned bound.

The report computes completion rate, decisive-result rate among completed
probes, requested planner cost, total and mean uncertainty reduction,
downstream decision IDs unlocked, and disagreement with determinate static
predictions. Rates are integer parts per million; uncertainty and cost ratios
use integer milli-units. A result is decisive when the consumer reports
`accept`/`reject`, or when its uncertainty reduction meets the caller's
predeclared threshold. Caller predictions, uncertainty labels, receipt
truthfulness, and the claim that an unresolved set was frozen before capture
cannot be independently authenticated by this evaluator.

The evaluator never executes probes. It rejects a receipt that exceeds the
plan's step or time budget, and it does not infer completion for a missing
receipt. Cost units are the planner's relative request-cost scale; actual
steps and milliseconds are also reported so the measures remain distinct.

```sh
python -m revenginstr.runtime_probe_evaluation \
  docs/evidence/runtime-probe-evaluation-v1/nevergone-synthetic/evaluation-manifest.json \
  docs/evidence/runtime-probe-evaluation-v1/nevergone-synthetic/request-plan.json \
  docs/evidence/runtime-probe-evaluation-v1/nevergone-synthetic/outcomes.jsonl \
  --output /tmp/runtime-probe-evaluation.json
```

The checked-in Nevergone-shaped set is synthetic. It exercises arithmetic and
schema contracts; it is not evidence for the M9 exit-rate targets. A real
frozen unresolved set and consumer-collected device outcomes are still needed
to measure project performance.
