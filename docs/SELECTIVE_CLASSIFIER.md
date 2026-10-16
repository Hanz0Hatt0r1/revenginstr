# Selective classifier

`REVENGINSTR.SelectiveClassifier/1` is the first project-neutral classifier artifact extracted from the Nevergone ML lineage.

It deliberately preserves only the generic mechanism:

```text
portable P-code ops
  -> TF-IDF unigram/bigram
  -> balanced logistic regression
  -> family-grouped OOF correctness calibration
  -> classwise accept/review thresholds
  -> predicted-family similarity
  -> strongest competing-family similarity
  -> contrastive OOD gate
  -> accept / review / escalate
```

Game-specific class names, label rules, addresses, object layouts and deployment policy remain consumer-owned.

## Dataset contract

Training consumes a directory with any subset of:

```text
train.jsonl
validation.jsonl
test.jsonl
```

Each selected row contains:

```json
{"id":"...","text":"...","labels":{"code_domain":"..."}}
```

The family file is `REVENGINSTR.FunctionFamilies/1` JSONL and supplies `id -> family_id`.

`text` may be the full portable corpus `model_text`; only P-code operation lines are retained. Corpus headers, program identity, function names and source addresses are excluded from the classifier document.

## Training

Install ML dependencies:

```bash
python -m pip install -e '.[ml]'
```

Train:

```bash
revenginstr-selective-train dataset families.jsonl model \
  --task code_domain \
  --classes game engine runtime_library media_library
```

Outputs:

```text
model/classifier.joblib
model/manifest.json
model/oof_predictions.jsonl
```

The manifest records family-held-out fold metrics, classwise routing policy, selective precision/coverage and the leakage policy.

## Inference

```bash
revenginstr-selective-infer model corpus.jsonl --output predictions.jsonl
```

Each row includes prediction, calibrated correctness confidence, action, predicted-family similarity, competing-family similarity and contrast margin.

## Cross-project use

A classifier trained on project A may be run on project B only as structural/OOD triage unless project B has independent labels and calibration. The generic `revenginstr-foreign-guard` remains appropriate for foreign-project use because it can only demote `accept -> review`.

`accept` from a foreign model is never semantic proof by itself.

## Migration compatibility

The mechanism corresponds to the proven Nevergone P-code-only contrastive family classifier, but the artifact format is intentionally new. Consumer repositories should keep historical `NEVERGONE.ProductionClassifier/*` artifacts immutable and migrate by retraining or by an explicit consumer-side converter, not by silently relabeling old joblib files.
