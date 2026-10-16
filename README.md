# revenginstr

Reusable reverse-engineering analysis tooling extracted from the Nevergone and NFS Shift recompilation projects.

`revenginstr` is the project-neutral analysis core. Game-specific labels, addresses, class names, offsets, datasets and semantic evidence remain in consumer repositories.

## Current core

The repository now owns these generic mechanisms:

- architecture-normalized high-P-code export from Ghidra;
- direct-call resolution that tolerates low-bit-tagged code pointers when the normalized target is a known function;
- portable corpus/schema validation and leakage audits;
- cross-project/OOD diagnostics and monotone foreign-project guards;
- callgraph metric extraction;
- mass indirect-call receiver/type acquisition;
- conservative receiver class/vtable identity inference from consumer-owned catalogs;
- leakage-safe evidence aggregation;
- deterministic structural P-code metrics and coarse numeric evidence tokenization;
- portable P-code function-family mining with deterministic MinHash/LSH;
- family-grouped selective classification with calibrated correctness confidence and contrastive family OOD;
- optional evidence-aware selective classification using `REVENGINSTR.Evidence/1`;
- family-grouped accept-error production routing with monotone `accept -> escalate` correction;
- deterministic identity-disjoint frozen validation with SHA-256 provenance;
- unlabeled distribution-shift diagnostics for predictions, routing and evidence coverage;
- compatibility hash profile for historical Nevergone family groups.

Stable component formats currently include:

```text
REVENGINSTR.PcodeCorpus/1
REVENGINSTR.PcodeAudit/1
REVENGINSTR.ForeignGuard/1
REVENGINSTR.CallGraphMetrics/1
REVENGINSTR.ReceiverPlan/1
REVENGINSTR.GhidraIndirectReceiverType/1
REVENGINSTR.ReceiverInference/1
REVENGINSTR.Evidence/1
REVENGINSTR.FunctionFamilies/1
REVENGINSTR.SelectiveClassifier/1
REVENGINSTR.EvidenceSelectiveClassifier/1
REVENGINSTR.AcceptErrorRouter/1
REVENGINSTR.FrozenValidation/1
REVENGINSTR.DriftAudit/1
```

JSON Schemas in `schemas/` define the portable P-code corpus, callgraph metrics,
and aggregated evidence records. Source identifiers remain join metadata; evidence
features are numeric or boolean, project-neutral summaries.

## Boundary

The toolkit may know about architectures such as ARM32 and x86-32 and generic concepts such as P-code, callgraphs, receivers, vtables, family similarity, OOD, selective routing and distribution shift.

It must not encode Nevergone `GameScene`/Cocos rules, NFS Shift retail addresses/`HDVehicle` offsets, or any other title-specific semantic truth.

Current consumers:

- `Hanz0Hatt0r1/nevergone-recomp` — reference/training consumer;
- `Hanz0Hatt0r1/nfs-shift-decompilation` — first cross-project x86-32 consumer.

## Layout

```text
ghidra/                        generic Ghidra exporters
scripts/                       read-only/noanalysis Ghidra runners
src/revenginstr/pcode/         portable corpus audits
src/revenginstr/ood/           cross-project safety guards
src/revenginstr/evidence/      callgraph + structural + aggregated evidence
src/revenginstr/receiver/      receiver planning/inference
src/revenginstr/family/        portable family features/mining
src/revenginstr/ml/            project-neutral classifiers and routers
src/revenginstr/validation/    frozen holdout + drift diagnostics
schemas/                       stable data contracts
tests/                         project-neutral tests
docs/                          architecture/migration notes
```

## Install

For sibling consumer repositories:

```bash
cd ~
git clone https://github.com/Hanz0Hatt0r1/revenginstr.git
python -m pip install -e ~/revenginstr
```

Development setup:

```bash
cd ~/revenginstr
python -m pip install -e '.[test,ml]'
pytest
```

Nevergone and NFS Shift runners can use a sibling `~/revenginstr` checkout and `PYTHONPATH` directly, so editable installation is convenient rather than mandatory. Once installed, the analysis/validation CLIs operate on local files and do not require a remote service.

## CLI examples

```bash
revenginstr-pcode-audit corpus.jsonl
revenginstr-callgraph corpus.jsonl functions.tsv.gz calls.tsv.gz --output callgraph.jsonl
revenginstr-receiver-plan trace.jsonl receiver-plan.tsv --program game.exe
revenginstr-receiver-infer receiver-types.tsv catalog.jsonl --output receiver-inference.jsonl
revenginstr-evidence-aggregate trace.jsonl \
  --callgraph-metrics callgraph.jsonl \
  --receiver-types receiver-types.tsv \
  --receiver-inference receiver-inference.jsonl \
  --output evidence.jsonl
revenginstr-family-mine dataset families.jsonl
revenginstr-selective-train dataset families.jsonl model \
  --task code_domain --classes game engine runtime_library media_library
revenginstr-selective-infer model corpus.jsonl --output predictions.jsonl
revenginstr-evidence-selective-train dataset families.jsonl model-v2 \
  --evidence evidence.jsonl \
  --task code_domain --classes game engine runtime_library media_library
revenginstr-evidence-selective-infer model-v2 corpus.jsonl \
  --evidence evidence.jsonl --output predictions-v2.jsonl
revenginstr-accept-router-train model-v2/oof_predictions.jsonl accept-router \
  --evidence evidence.jsonl --target-accept-precision 0.97
revenginstr-accept-router-infer accept-router predictions-v2.jsonl \
  --evidence evidence.jsonl --output routed.jsonl
revenginstr-freeze-validation wide-corpus.jsonl validation/unseen500 \
  --exclude-trace training-trace.jsonl --limit 500 --tag unseen500-v1
revenginstr-drift-audit model-v2/oof_predictions.jsonl validation/unseen500/routed.jsonl \
  --reference-evidence evidence.jsonl \
  --frozen-evidence validation/unseen500/evidence.jsonl \
  --router-manifest accept-router/manifest.json \
  --output validation/unseen500/drift.json
```

For an existing analyzed Ghidra project:

```bash
GHIDRA_HOME=/opt/ghidra \
  scripts/run_ghidra_pcode_export.sh \
  /path/to/projects project-name program-name corpus.jsonl 1000
```

The Ghidra runners are `-readOnly -noanalysis`; they consume an existing analysis database rather than silently changing it.

## Portable P-code contract

`model_text` deliberately excludes function names, absolute addresses, direct call target identity, strings/resources, instruction bytes and decompiler C. Outer `program`, `source_entry` and `source_name` fields are audit/join metadata only.

Function-family mining excludes headers from the portable view. The CLI uses the generic `revenginstr-v1` MinHash profile. Callers that need deterministic historical seeds can pass a `HashProfile` to the Python API and keep those seed values in their consumer adapter.

The P-code-only selective classifier trains only on the portable operation view. The evidence-aware variant additionally receives deterministic structural summaries and coarse bucketed numeric `REVENGINSTR.Evidence/1` features. Family IDs are grouping/OOD metadata and labels are targets, never model features.

The accept-error router is trained only from already-held-out base predictions and family groups. It preserves class predictions and all non-accept actions; it can only downgrade a questionable base `accept` to `escalate`.

Frozen validation is also project-neutral: consumers provide training/calibration trace identities, while revenginstr handles deterministic selection, immutability hashes and deployment-drift diagnostics. Frozen unlabeled data never becomes semantic ground truth merely because a model produced predictions for it.

## Consumer contract

Consumer repositories own:

- binaries and reverse-engineering evidence;
- datasets and ground-truth/weak labels;
- class/vtable catalog contents;
- title-specific addresses and object-layout knowledge;
- semantic gates and deployment decisions;
- historical experiment/model lineage;
- the trace identities that define what counts as training/calibration overlap.

Cross-project model output is triage/OOD evidence, not semantic authority. Generic algorithms must not close a consumer's semantic proof gate on their own.

See `docs/MIGRATION.md`, `docs/SELECTIVE_CLASSIFIER.md`, `docs/EVIDENCE_SELECTIVE_CLASSIFIER.md`, `docs/ACCEPT_ERROR_ROUTER.md` and `docs/FROZEN_VALIDATION.md`.
