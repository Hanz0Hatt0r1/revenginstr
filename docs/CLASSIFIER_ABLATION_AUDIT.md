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

## Declared feature-group removals

For experiments that remove evidence groups, use
`REVENGINSTR.ClassifierAblationSet/2`. It keeps the same pinned model and OOF
inputs and adds a feature inventory plus the groups removed by each variant:

```json
{
  "format": "REVENGINSTR.ClassifierAblationSet/2",
  "baseline": "full",
  "feature_groups": ["callgraph", "external_call", "field", "pcode", "receiver"],
  "variants": {
    "full": {
      "manifest_path": "full/manifest.json",
      "manifest_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
      "oof_predictions_path": "full/oof_predictions.jsonl",
      "oof_predictions_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
      "removed_feature_groups": []
    },
    "without_receiver": {
      "manifest_path": "without-receiver/manifest.json",
      "manifest_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
      "oof_predictions_path": "without-receiver/oof_predictions.jsonl",
      "oof_predictions_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
      "removed_feature_groups": ["receiver"]
    }
  }
}
```

The `/2` audit validates that the baseline removes nothing, each comparison
removes at least one declared group, and no variant names a group outside the
inventory. Its report records the declared removed and retained groups beside
the paired metric deltas. Group names use lowercase snake_case; common names
include `pcode`, `callgraph`, `receiver`, `field`, `external_call`, and
`family`.

This is experiment metadata, not proof that the training pipeline applied the
declared removal. The referenced manifests and OOF files are hash-pinned, while
the caller remains responsible for producing each model with the stated
feature set. `/1` inputs and reports remain supported unchanged. Neither OOF
version substitutes for a disjoint frozen-family evaluation.
