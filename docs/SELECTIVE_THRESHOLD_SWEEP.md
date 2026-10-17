# Selective threshold sweep

`REVENGINSTR.SelectiveThresholdSweep/1` audits classwise precision/coverage
thresholds over a selective classifier's family-grouped out-of-fold (OOF)
predictions. It does not train or modify a model and is not used by inference.

```sh
revenginstr-selective-threshold-sweep model/manifest.json \
  model/oof_predictions.jsonl --output threshold-sweep.json \
  --target-precision 0.85 --target-precision 0.90 \
  --target-precision 0.95 --target-precision 0.97 --min-examples 10
```

The command requires the manifest to identify `family_grouped_oof` calibration.
It also checks that prediction row count, family count, and truth distribution
match the manifest, that `correct` agrees with `truth` and `prediction`, and
that ids are unique. The report includes SHA-256 digests for both inputs.

For each predicted class and target precision, the sweep selects the lowest
confidence threshold that meets the target with at least `min_examples`, which
maximizes accepted coverage. Coverage is measured within that predicted class.
The report distinguishes feasible thresholds from missing predictions,
insufficient examples, and unmet precision targets.

The thresholds are selected and measured on the same OOF population, so the
report is exploratory calibration evidence. Use an independent frozen family
split for final performance claims; this audit does not change deployment
thresholds or establish target-project accuracy.
