# Classifier error buckets

`REVENGINSTR.ClassifierErrorBuckets/1` summarizes errors from a
family-disjoint `SelectiveThresholdEvaluation/1` population by truth/prediction
pair, routing action, and calibrated correctness confidence.

```sh
revenginstr-classifier-error-buckets threshold-evaluation.json \
  frozen-evaluation-predictions.jsonl --output error-buckets.json
```

The evaluator report must declare family-disjoint evaluation and contain the
SHA-256 of the exact prediction file supplied to this command. Rows must have
unique ids, matching truth/prediction/correct fields, a valid route action,
and family ids/counts consistent with the evaluation report.

Each bucket reports error and family counts, `accept`/`review`/`escalate`
counts, and confidence range/mean. The summary includes total error rate and
accepted-error count. The report omits function ids and family ids; class names
remain the caller's label vocabulary. It is an audit of the supplied holdout
and does not tune model thresholds or imply transfer to another project.
