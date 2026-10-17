# Classifier ablation audit

`REVENGINSTR.ClassifierAblationAudit/1` compares named classifier runs using
their family-grouped out-of-fold predictions. The caller prepares a
`REVENGINSTR.ClassifierAblationSet/1` JSON file with a baseline and at least one
variant:

```json
{
  "format": "REVENGINSTR.ClassifierAblationSet/1",
  "baseline": "pcode_only",
  "variants": {
    "pcode_only": {
      "manifest_path": "pcode/manifest.json",
      "manifest_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
      "oof_predictions_path": "pcode/oof_predictions.jsonl",
      "oof_predictions_sha256": "0000000000000000000000000000000000000000000000000000000000000000"
    },
    "with_evidence": {
      "manifest_path": "evidence/manifest.json",
      "manifest_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
      "oof_predictions_path": "evidence/oof_predictions.jsonl",
      "oof_predictions_sha256": "0000000000000000000000000000000000000000000000000000000000000000"
    }
  }
}
```

Replace the placeholder digests with the SHA-256 of each referenced file.

Run the audit with:

```sh
revenginstr-classifier-ablation-audit ablation-set.json --output ablation-audit.json
```

Each run must use the same dataset fingerprint, class list, seed, fold count,
OOF ids, family ids, and truth labels. Both
`SelectiveClassifier/1` and `EvidenceSelectiveClassifier/1` runs are
supported. The report includes accuracy, balanced accuracy, macro-F1,
per-class counts, route acceptance metrics, changed predictions, fixed errors,
introduced errors, and deltas from the baseline. It records hashes for the set,
manifests, and prediction files, while omitting record and family ids.

Variant names and feature-removal semantics belong to the caller. The audit
does not verify that a run actually removed a named feature and does not treat
crossfit OOF comparisons as an independent frozen holdout result.
