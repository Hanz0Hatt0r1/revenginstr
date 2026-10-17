# Selective threshold evaluation

`REVENGINSTR.SelectiveThresholdEvaluation/1` applies classwise thresholds
selected from family-grouped OOF predictions to a separate evaluation
population. The evaluation report is read-only and does not alter a model or
deployment policy.

```sh
revenginstr-selective-threshold-evaluate model/manifest.json \
  model/oof_predictions.jsonl frozen-evaluation-predictions.jsonl \
  --output threshold-evaluation.json \
  --target-precision 0.90 --target-precision 0.95 \
  --min-train-examples 10 --bins 10
```

Evaluation rows use the selective prediction format plus consumer-joined
`truth` and `family_id` fields. The tool checks unique ids, label consistency,
and that evaluation ids and families do not overlap the OOF population. It
retains SHA-256 digests for the classifier manifest and both prediction files;
pin the evaluation file in a benchmark manifest for a reproducible frozen
split.

For each predicted class, the report gives held-out accuracy, Brier score,
expected calibration error, and confidence/accuracy bins. At each target
precision it also reports OOF training precision/coverage beside precision
and class-local coverage after applying the unchanged training threshold to
the held-out rows. Classes without an available OOF threshold or evaluation
predictions remain explicit in the report.

The tool proves family-id disjointness between the supplied files; it does not
prove that the caller selected the correct frozen dataset or semantic labels.
The consumer owns those labels and dataset-selection provenance.
