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

### Consumer-owned eligibility

Some projects need title-specific population rules before random/frozen selection.
Examples include excluding compiler/runtime scaffolding, known third-party libraries
or functions outside a semantic research frontier. Those rules must stay in the
consumer repository rather than being embedded in `revenginstr`.

The consumer can write an eligibility trace containing `id` and/or
`program` + `source_entry` for every allowed function, then pass it to the generic
selector:

```bash
revenginstr-freeze-validation \
  wide-corpus.jsonl \
  validation/unseen500 \
  --eligible-trace consumer-eligible-functions.jsonl \
  --exclude-trace training-trace.jsonl \
  --limit 500 \
  --tag unseen500-v1
```

Multiple `--eligible-trace` and `--exclude-trace` arguments are allowed. Eligibility
traces form a union of allowed identities; exclusion traces form a union of blocked
identities. Eligibility is applied first, then training/calibration overlap is
removed.

This boundary lets a consumer preserve project-specific origin decisions without
teaching the common validation core about Cocos, EA libraries, retail addresses,
compiler scaffolding or any other title-specific semantics.

The selector:

1. accepts only successful `REVENGINSTR.PcodeCorpus/1` rows;
2. excludes external rows by default;
3. optionally restricts the population to consumer-provided eligibility traces;
4. removes any identity present in an exclusion trace;
5. removes duplicate physical identities;
6. ranks remaining rows by a stable SHA-256 selection key;
7. writes exactly the requested number of rows;
8. writes immutable source/eligibility/exclusion/corpus/trace SHA-256 provenance.

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

### Retained historical action baselines

A consumer may have a historical routing baseline whose actions are not identical
to the `action` field in the retained classifier OOF file. To reproduce drift
statistics without teaching the generic core about experiment names or versions,
provide a companion JSONL containing the exact same ids and either `base_action` or
`action`:

```bash
revenginstr-drift-audit \
  historical/base-oof.jsonl \
  historical/frozen-routed.jsonl \
  --reference-base-actions historical/base-actions.jsonl \
  --router-manifest historical/router/manifest.json \
  --reference-evidence historical/evidence.jsonl \
  --frozen-evidence historical/frozen-evidence.jsonl \
  --output historical/drift-reproduced.json
```

The companion population must match the reference population exactly. Missing,
duplicate or extra ids fail closed. When the reference rows do not themselves
contain `accept_router_changed`, the router manifest supplies the retained number of
accepted rows demoted by the historical router; routed-action distribution is then
reconstructed from the overlaid baseline counts without inventing row-level
correctness.

This mechanism is intended for migration/parity and long-lived experiment lineage.
It remains project-neutral: the consumer owns how a historical action is extracted.

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

## Schemas

Stable JSON Schema contracts are provided for the manifest/report surfaces:

```text
schemas/frozen-validation-v1.schema.json
schemas/drift-audit-v1.schema.json
```

The frozen manifest hashes the eligibility traces as well as exclusion traces, so
consumer population policy becomes part of the retained provenance.

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
