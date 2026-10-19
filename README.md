# revenginstr

Reusable reverse-engineering analysis tooling extracted from the Nevergone and NFS Shift recompilation projects.

`revenginstr` is the project-neutral analysis core. Game-specific labels, addresses, class names, offsets, datasets and semantic evidence remain in consumer repositories.

## Current core

The repository now owns these generic mechanisms:

- architecture-normalized high-P-code export from Ghidra;
- direct-call resolution that tolerates low-bit-tagged code pointers when the normalized target is a known function;
- bounded forward and reverse direct-call graph High-P-code export from Ghidra, with consumer-configurable symbol ordering;
- portable corpus/schema validation and leakage audits;
- cross-project/OOD diagnostics and monotone foreign-project guards;
- callgraph metric extraction;
- mass indirect-call receiver/type acquisition;
- read-only ARM32 Itanium primary-vtable slot export from Ghidra;
- targeted data and direct-reference export for caller-selected Ghidra addresses;
- bounded High-P-code field-store candidates scoped by caller-selected function-name fragments and offsets;
- parameter-to-parameter field-store provenance through bounded P-code address and value expressions;
- targeted High-P-code basic-block CFG export with operation sequence locations;
- provenance-pinned field store/load CFG path candidates with explicit store/call barriers;
- targeted listing, memory-block, symbol and function metadata export by address;
- bounded High-P-code indirect-call target evidence;
- read-only full-program metadata indexing for functions, symbols, strings, references and direct calls;
- targeted machine-instruction, control-flow, reference and P-code export from Ghidra;
- bounded instruction slices with machine P-code, flow and reference context;
- compact whole-program instruction streams with optional gzip storage;
- exact scalar-use inventory with candidate-only mnemonic categories;
- targeted numeric-operand and referenced-scalar export from Ghidra;
- conservative receiver class/vtable identity inference from consumer-owned catalogs;
- leakage-safe evidence aggregation;
- deterministic structural P-code metrics and coarse numeric evidence tokenization;
- hash-pinned runtime/static address correlation, pairwise differential summaries, and repeated intervention evidence;
- portable P-code function-family mining with deterministic MinHash/LSH;
- family-grouped selective classification with calibrated correctness confidence and contrastive family OOD;
- optional evidence-aware selective classification using `REVENGINSTR.Evidence/1`;
- family-grouped accept-error production routing with monotone `accept -> escalate` correction;
- deterministic identity-disjoint frozen validation with SHA-256 provenance;
- a hash-pinned benchmark manifest and dependency-ordered smoke/full runner;
- standardized benchmark projections, deterministic replay, and summary deltas;
- unlabeled distribution-shift diagnostics for predictions, routing and evidence coverage;
- provenance-linked function effects and compact structural function summaries;
- compatibility hash profile for historical Nevergone family groups.

Stable component formats currently include:

```text
REVENGINSTR.PcodeCorpus/1
REVENGINSTR.PcodeAudit/1
REVENGINSTR.ForeignGuard/1
REVENGINSTR.CallGraphMetrics/1
REVENGINSTR.ReceiverPlan/1
REVENGINSTR.GhidraIndirectReceiverType/1
REVENGINSTR.GhidraArm32ItaniumVtableSlots/1
REVENGINSTR.GhidraFunctionPcodeFlow/1
REVENGINSTR.GhidraFunctionPcodeCFG/1
REVENGINSTR.GhidraFunctionPcodeCFG/2
REVENGINSTR.FieldStoreLoadDominanceAudit/1
REVENGINSTR.GhidraPcodeDefinedString/1
REVENGINSTR.GhidraAddressReferenceOwner/1
REVENGINSTR.GhidraAddressReferences/1
REVENGINSTR.GhidraFunctionInstructions/1
REVENGINSTR.GhidraInstructionSlice/1
REVENGINSTR.GhidraCompactInstructionStream/1
REVENGINSTR.GhidraScalarUses/1
REVENGINSTR.GhidraFieldStoreCandidates/1
REVENGINSTR.GhidraParameterStoreField/1
REVENGINSTR.FieldStoreLoadPathAudit/1
REVENGINSTR.GhidraFunctionOperand/1
REVENGINSTR.GhidraAddressMetadata/1
REVENGINSTR.GhidraIndirectCallEvidence/1
REVENGINSTR.ReceiverInference/1
REVENGINSTR.Evidence/1
REVENGINSTR.FunctionFamilies/1
REVENGINSTR.SelectiveClassifier/1
REVENGINSTR.EvidenceSelectiveClassifier/1
REVENGINSTR.AcceptErrorRouter/1
REVENGINSTR.FrozenValidation/1
REVENGINSTR.DriftAudit/1
REVENGINSTR.BenchmarkManifest/1
REVENGINSTR.BenchmarkSummary/1
REVENGINSTR.DeterminismAudit/1
REVENGINSTR.BenchmarkDelta/1
REVENGINSTR.FunctionEffectIR/1
REVENGINSTR.FunctionEffectIR/2
REVENGINSTR.FunctionSummary/1
REVENGINSTR.FunctionSummary/2
REVENGINSTR.AnalysisFeedback/1
REVENGINSTR.AnalysisDecisionLedgerEvent/1
REVENGINSTR.AnalysisDecisionLedgerAudit/1
REVENGINSTR.RuntimeStaticIdentity/1
REVENGINSTR.RuntimeCaptureManifest/1
REVENGINSTR.RuntimeAddressObservation/1
REVENGINSTR.RuntimeStaticCorrelation/1
REVENGINSTR.RuntimeDifferentialManifest/1
REVENGINSTR.RuntimeDifferential/1
REVENGINSTR.RuntimeInterventionManifest/1
REVENGINSTR.RuntimeInterventionEvidence/1
REVENGINSTR.RuntimeValueFlowManifest/1
REVENGINSTR.RuntimeValueObservation/1
REVENGINSTR.RuntimeValueFlowReplay/1
REVENGINSTR.RuntimeProbeEvaluationManifest/1
REVENGINSTR.RuntimeProbeOutcome/1
REVENGINSTR.RuntimeProbeEvaluation/1
```

JSON Schemas in `schemas/` define portable evidence, benchmark, determinism and
metric-delta contracts. Source identifiers remain join metadata; evidence
features are numeric or boolean, project-neutral summaries. The normative
field, ordering, provenance and compatibility index is
[`docs/SCHEMA_CONTRACTS.md`](docs/SCHEMA_CONTRACTS.md).
The `GhidraFunctionPcodeFlow/1` metadata-only TSV contract is documented in
`docs/GHIDRA_FUNCTION_PCODE_FLOW.md`.
The `GhidraPcodeDefinedString/1` TSV contract resolves only defined strings
referenced by constant tokens in a P-code TSV; string values are base64 encoded.
See `docs/GHIDRA_PCODE_DEFINED_STRINGS.md` for the exporter contract and runner.
`GhidraAddressReferenceOwner/1` lists direct reference locations for
caller-supplied addresses; see `docs/GHIDRA_ADDRESS_REFERENCE_OWNERS.md`.
The `GhidraFieldStoreCandidates/1` TSV contract and bounded STORE exporter are
documented in `docs/GHIDRA_FIELD_STORE_CANDIDATES.md`.
Exact scalar-use inventory and its generic Ghidra runner are documented in
`docs/GHIDRA_SCALAR_USES.md`.
Exact-address instruction-slice exports and their generic Ghidra runner are
documented in `docs/GHIDRA_INSTRUCTION_SLICES.md`.
Compact whole-program instruction streams and their gzip-aware runner are
documented in `docs/GHIDRA_COMPACT_INSTRUCTION_STREAM.md`.
The parameter-to-field store TSV contract is documented in
`docs/GHIDRA_PARAMETER_STORE_FIELD.md`.
The consumer-owned reviewer feedback contract is documented in
[`docs/ANALYSIS_FEEDBACK.md`](docs/ANALYSIS_FEEDBACK.md).
The convergence-state and decision-ledger contracts are documented in
[`docs/ANALYSIS_DECISION_LEDGER.md`](docs/ANALYSIS_DECISION_LEDGER.md).
The function-level evidence projection and compact structured summary are
documented in [`docs/FUNCTION_EFFECT_IR.md`](docs/FUNCTION_EFFECT_IR.md) and
[`docs/FUNCTION_SUMMARY.md`](docs/FUNCTION_SUMMARY.md).
Runtime address correlation, pairwise differential comparison, and repeated
intervention evidence are documented in
[`docs/RUNTIME_DIFFERENTIAL.md`](docs/RUNTIME_DIFFERENTIAL.md) and
[`docs/RUNTIME_INTERVENTION.md`](docs/RUNTIME_INTERVENTION.md).

The generic Ghidra function-instruction export is documented in
docs/GHIDRA_FUNCTION_INSTRUCTIONS.md.

The generic numeric function-operand export is documented in
docs/GHIDRA_FUNCTION_OPERANDS.md.

The generic Ghidra address-metadata export is documented in
docs/GHIDRA_ADDRESS_METADATA.md.

The generic indirect-call evidence export is documented in
docs/GHIDRA_INDIRECT_CALL_EVIDENCE.md.

The generic Ghidra program metadata index is documented in
docs/GHIDRA_PROGRAM_INDEX.md.

The ARM32 Itanium vtable-slot exporter and its row contract are documented in
[`docs/GHIDRA_VTABLE_SLOTS.md`](docs/GHIDRA_VTABLE_SLOTS.md).

The generic address-reference exporter is documented in
docs/GHIDRA_ADDRESS_REFERENCES.md.

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
python -m pip install -e '.[test,ml,benchmark]'
pytest
```

Consumer benchmark datasets remain outside this repository. A manifest pins
their identities and hashes, runs the selected project-neutral stages and
emits a machine-readable metric/gate summary. See [docs/BENCHMARKS.md](docs/BENCHMARKS.md).

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
revenginstr-accept-router-gate frozen-routed.jsonl accept-router/manifest.json \
  model-v2/oof_predictions.jsonl --output frozen-router-gate.json --strict
revenginstr-kpi-dashboard benchmarks/dashboard.json \
  --json-output build/kpi-dashboard.json \
  --markdown-output build/kpi-dashboard.md
revenginstr-effect-ir --program-id 'analysis:opaque-id' \
  --parameter-loads parameter-loads.tsv --output function-effects.jsonl
revenginstr-structured-summary function-effects.jsonl \
  --output function-summaries.jsonl
revenginstr-decision-ledger-audit decision-events.jsonl \
  --output decision-ledger-audit.json
revenginstr-receiver-field-store-load-audit field-access-pairs.jsonl \
  function-pcode-cfg.jsonl --output field-path-candidates.jsonl
revenginstr-receiver-field-store-load-dominance-audit field-access-pairs.jsonl \
  function-pcode-cfg-v2.jsonl --output field-store-load-dominance.jsonl
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

GHIDRA_HOME=/opt/ghidra \
  scripts/run_ghidra_function_pcode_flow.sh \
  /path/to/projects project-name program-name 00401000 function-flow.tsv

GHIDRA_HOME=/opt/ghidra \
  scripts/run_ghidra_function_pcode_cfg.sh \
  /path/to/projects project-name program-name function-pcode-cfg.jsonl \
  'analysis:opaque-id' 00401000

GHIDRA_HOME=/opt/ghidra \
  scripts/run_ghidra_pcode_defined_strings.sh \
  /path/to/projects project-name program-name function-flow.tsv defined-strings.tsv

GHIDRA_HOME=/opt/ghidra \
  scripts/run_ghidra_address_reference_owners.sh \
  /path/to/projects project-name program-name references.tsv 00401000 00402000
```

The Ghidra runners are `-readOnly -noanalysis`; they consume an existing analysis database rather than silently changing it.

For ARM32 Itanium binaries, `scripts/run_ghidra_vtable_slots.sh` exports the
contiguous primary function-pointer prefix for each detected vtable. Its TSV
contains program-specific symbols and addresses from the selected Ghidra project;
the exporter implementation and output contract remain project-neutral.

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
