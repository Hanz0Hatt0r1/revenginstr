# Retaining classifier hard negatives

`REVENGINSTR.ClassifierHardNegativeSet/1` writes selected errors from a
family-disjoint `SelectiveThresholdEvaluation/1` population as a caller-owned
review artifact.

```sh
revenginstr-retain-hard-negatives threshold-evaluation.json \
  frozen-evaluation-predictions.jsonl \
  --minimum-confidence 0.9 --action accept --output hard-negatives.json
```

The evaluator report must pin the exact prediction file. By default, the tool
retains only misclassified `accept` rows whose calibrated correctness
confidence is at least `0.9`; callers may select other route actions or a
different confidence floor. The output includes selected ids, family ids,
truth/prediction labels, confidence, and action, plus hashes of the evaluation
inputs and the selection criteria.

These examples are intended for human review and belong in the consumer
repository that owns their ids and labels. The tool does not modify training
data, trigger retraining, or treat a selected example as an independent
validation result.
