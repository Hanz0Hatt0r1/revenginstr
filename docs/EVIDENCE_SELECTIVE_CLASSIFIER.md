# Evidence-aware selective classifier

`REVENGINSTR.EvidenceSelectiveClassifier/1` generalizes the Nevergone v5 evidence-fusion mechanism without importing title-specific feature names or semantic rules into the shared toolkit.

It is deliberately a separate artifact from `REVENGINSTR.SelectiveClassifier/1` so the portable P-code-only baseline remains stable and suitable for cross-project representation/OOD tests.

## Representation

Every training/inference document contains:

1. the portable P-code operation view;
2. deterministic structural metrics derived from that view;
3. optional numeric `REVENGINSTR.Evidence/1` features supplied by the consumer.

Numeric features are emitted as coarse sparse tokens:

```text
EV|<sanitized-key>|<bucket>
```

Ratios in `[-1, 1]` use decile buckets. Other magnitudes use expanding power-of-two-like ranges. Raw high-precision values do not enter TF-IDF documents.

Structural features cover operation/memory/call/branch/control-flow densities, compare/arithmetic/bitwise/conversion/pointer counts, SSA merges, copy/slice operations and conservative definition-coverage proxies.

## Leakage boundary

The generic trainer never adds:

- source/function names;
- absolute addresses;
- raw receiver class names;
- raw vtable identities;
- binary/project identity;
- labels as model features.

Consumer-produced evidence must obey the same boundary. `REVENGINSTR.Evidence/1` is designed for numeric/categorical-summary features; project-specific adapters remain responsible for excluding raw identities before aggregation.

## Training

```bash
revenginstr-evidence-selective-train \
  dataset \
  families.jsonl \
  model \
  --evidence evidence.jsonl \
  --task code_domain \
  --classes game engine runtime_library media_library
```

The classifier then uses the same family-grouped OOF calibration and contrastive family OOD routing as the P-code-only baseline.

Outputs:

```text
model/classifier.joblib
model/manifest.json
model/oof_predictions.jsonl
```

The manifest records the external-evidence fingerprint, evidence coverage, mean token count, calibration metrics and selective routing metrics.

## Inference

```bash
revenginstr-evidence-selective-infer \
  model corpus.jsonl \
  --evidence evidence.jsonl \
  --output predictions.jsonl
```

Missing external evidence is allowed. Structural tokens are still generated for every valid portable P-code row.

## Consumer migration

Nevergone should retain `NEVERGONE.ProductionClassifier/5` and later experiment artifacts as immutable lineage. Migration is by retained parity/reproduction tests, not by renaming old joblib payloads.

NFS Shift should not use a Nevergone-trained evidence-aware artifact as semantic authority. Before a Shift-specific evidence model exists, the P-code-only generic classifier plus monotone foreign-project guard remains the safer cross-project triage path.
