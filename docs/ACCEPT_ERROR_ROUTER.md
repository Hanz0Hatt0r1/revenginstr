# Accept-error router

`REVENGINSTR.AcceptErrorRouter/1` is a project-neutral monotone routing layer for
selective classifiers.

It is extracted from the Nevergone v9/v10 accept-error work, but the implementation
contains no Nevergone classes, addresses, thresholds or title-specific evidence.
It supports any class set produced by a revenginstr selective classifier.

The component is local-first: training and inference operate on local JSONL/joblib
artifacts and require no remote service once `revenginstr[ml]` is installed.

## Purpose

A base selective classifier already decides among:

```text
accept / review / escalate
```

The accept-error router learns a second-stage probability that an already accepted
prediction is correct. It can only perform:

```text
accept -> accept
accept -> review|escalate
review -> review
escalate -> escalate
```

Promotions are impossible by construction.

## Training input

Use the `oof_predictions.jsonl` emitted by `revenginstr-selective-train` or
`revenginstr-evidence-selective-train`. Required fields are:

```text
id
family_id or fold
truth
prediction
correct
action
probabilities
family_similarity
competing_similarity
contrast_margin
```

If positive integer `fold` values are present, they are reused. Otherwise meta
cross-fitting derives deterministic folds from `family_id`; a family never crosses
meta folds.

Optional numeric evidence uses `REVENGINSTR.Evidence/1`. Keys containing obvious
identity/label material (`address`, `source_entry`, `function_name`, `symbol_name`,
raw class/vtable identity terms, etc.) are excluded from the meta feature schema.

The feature vector contains:

- aligned class probabilities;
- top-two probability gap;
- probability entropy and max probability;
- predicted-family similarity;
- competing-family similarity;
- contrast margin;
- predicted-class one-hot;
- sanitized numeric evidence.

## Train

```bash
revenginstr-accept-router-train \
  model/oof_predictions.jsonl \
  model/accept-router \
  --evidence evidence.jsonl \
  --target-accept-precision 0.97 \
  --max-accept-coverage-loss 0.04
```

Output:

```text
model/accept-router/
  accept_error_router.joblib
  manifest.json
```

The deployable threshold is selected from group-safe cross-fitted correctness
scores. The final meta models are then fitted on all leakage-safe legacy accept
rows. Cross-fitted metrics are calibration diagnostics; consumers remain
responsible for an independent frozen validation set.

## Apply

First run the base classifier, then route its JSONL:

```bash
revenginstr-evidence-selective-infer \
  model/base corpus.jsonl \
  --evidence evidence.jsonl \
  --output classified.jsonl

revenginstr-accept-router-apply \
  model/accept-router classified.jsonl \
  --evidence evidence.jsonl \
  --output routed.jsonl
```

Router output preserves the original prediction and adds:

```text
base_action
accept_router_format
accept_router_threshold
accept_correctness_probability
accept_router_changed
```

## Evaluation boundary

The router must not be tuned repeatedly against the same frozen holdout. Threshold
selection belongs to the OOF training/calibration surface; frozen/cross-project
sets are for validation and distribution-shift diagnostics.
