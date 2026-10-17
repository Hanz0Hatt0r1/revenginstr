# Selective subgroup audit

`REVENGINSTR.SelectiveSubgroupAudit/1` reports held-out classifier metrics for
groups assigned by the caller. It joins a `REVENGINSTR.EvaluationSubgroup/1`
JSONL sidecar to every prediction id in a family-disjoint
`SelectiveThresholdEvaluation/1` population.

```sh
revenginstr-selective-subgroup-audit threshold-evaluation.json \
  frozen-evaluation-predictions.jsonl evaluation-subgroups.jsonl \
  --output subgroup-audit.json
```

The evaluator report must hash the exact prediction file. The tool requires a
one-to-one sidecar mapping for the full evaluation set, checks family and row
counts against the evaluator report, and records hashes for all three inputs.
Each group reports accuracy, calibration, action counts, accepted precision
and coverage, plus per-class truth/prediction counts. The report omits record
and family ids.

Group names and their meanings are entirely caller-defined. The generic tool
does not classify a group as in-domain, out-of-domain, or otherwise preferred;
it only reports metrics for the supplied partition. It does not tune thresholds
or change classifier/router behavior.
