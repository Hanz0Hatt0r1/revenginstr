# Frozen validation and drift audit

`revenginstr` provides a local-first validation layer for keeping one immutable,
identity-disjoint deployment holdout per consumer/project generation.

Formats:

```text
REVENGINSTR.FrozenValidation/1
REVENGINSTR.DriftAudit/1
```

Neither format supplies semantic ground truth by itself. The drift audit is an
unlabeled diagnostic and must not be reported as accuracy/precision.

## Freeze a holdout

The generic Ghidra exporter emits `program` + `source_entry` join identity but does
not force a project-specific dataset ID scheme. Training consumers should therefore
provide one or more trace JSONL files containing the identities already consumed by
training/calibration.

```bash
revenginstr-freeze-validation \
  wide-corpus.jsonl \
  validation/unseen500 \
  --exclude-trace training-trace.jsonl \
  --limit 500 \
  --tag unseen500-v1
```

The selector:

1. accepts only successful `REVENGINSTR.PcodeCorpus/1` rows;
2. excludes external rows by default;
3. removes any identity present in an exclusion trace;
4. removes duplicate physical identities;
5. ranks remaining rows by a stable SHA-256 selection key;
6. writes exactly the requested number of rows;
7. writes immutable source/exclusion/corpus/trace SHA-256 provenance.

Output:

```text
validation/unseen500/
  corpus.jsonl
  trace.jsonl
  manifest.json
```

The selected corpus gets `id=program:source_entry` when the source row does not
already contain an ID. This matches the fallback join identity used by revenginstr
classifier inference.

The manifest refuses replacement by default. Creating a different tag does not
silently resample the population; selection is controlled by the explicit
`--selection-salt`. Only use `--overwrite` or a different selection salt when you
intend to create a new validation generation.

## Produce frozen classifications

Classification/evidence acquisition remains consumer-controlled. A typical local
flow is:

```bash
revenginstr-evidence-selective-infer \
  model/base \
  validation/unseen500/corpus.jsonl \
  --evidence validation/unseen500/evidence.jsonl \
  --output validation/unseen500/base-classified.jsonl

revenginstr-accept-router-infer \
  model/accept-router \
  validation/unseen500/base-classified.jsonl \
  --evidence validation/unseen500/evidence.jsonl \
  --output validation/unseen500/routed.jsonl
```

## Distribution-shift audit

Compare training/reference OOF behavior with frozen deployment behavior:

```bash
revenginstr-drift-audit \
  model/base/oof_predictions.jsonl \
  validation/unseen500/routed.jsonl \
  --reference-evidence training-evidence.jsonl \
  --frozen-evidence validation/unseen500/evidence.jsonl \
  --router-manifest model/accept-router/manifest.json \
  --output validation/unseen500/drift.json
```

The audit reports:

- Jensen-Shannon divergence for prediction/base-action/routed-action distributions;
- confidence, raw-confidence, family similarity, competing similarity, contrast,
  probability gap/max/entropy shifts;
- router intervention rate on legacy accept rows;
- numeric evidence-key coverage shifts;
- configurable core evidence coverage;
- a conservative `low` / `moderate` / `high` diagnostic severity.

Default generic core evidence keys are:

```text
has_callgraph
has_receiver_types
has_receiver_inference
```

Override the set by repeating `--core-evidence-key`.

## Interpretation

The severity label is a deployment diagnostic, not a semantic score. In particular:

- a higher router intervention rate can be healthy caution under distribution shift;
- a class-distribution shift does not imply classification error;
- evidence coverage loss can invalidate comparisons even when class/action
  distributions look stable;
- target-project labels or exact reverse-engineering proof are still required for
  semantic correctness claims.

Do not repeatedly resample or tune thresholds against the same frozen holdout.
Create a deliberately versioned new frozen generation instead.
