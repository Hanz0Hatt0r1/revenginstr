# revenginstr Development Roadmap

**Status:** active engineering plan  
**Baseline date:** 2026-10-17  
**Repository baseline:** `main` through `f413895740ee3e5c00673f22eabfb0e2a0237099`
**Scope:** project-neutral reverse-engineering analysis infrastructure: evidence extraction, indirect-dispatch recovery, receiver/type/vtable inference, ML classification, selective routing, semantic inference, orchestration, validation, and reusable interfaces.

> This roadmap describes the development of `revenginstr` itself. Game-specific addresses, class names, offsets, labels, binary-derived semantic truth and project-local datasets remain in consumer repositories such as Nevergone or NFS Shift.

## 1. North-star goal

`revenginstr` should be able to take a supported native binary plus an already analyzed Ghidra project and produce a reproducible, auditable analysis package containing:

1. canonical P-code and structural evidence;
2. direct and indirect callgraph evidence;
3. receiver/class/vtable hypotheses with provenance;
4. code-domain and subsystem predictions where a model is available;
5. function-level effect summaries;
6. semantic role hypotheses and state/object relationships;
7. calibrated `accept` / `review` / `escalate` decisions;
8. a decision ledger explaining why every important automatic conclusion was reached;
9. machine-readable artifacts consumable by decompilation/recompilation projects.

The system must prefer abstention over fabricated certainty. Model output is never promoted to exact evidence. Unsupported shapes, conflicts, schema mismatches and distribution shift must fail closed.

## 2. Current baseline

`revenginstr` already owns a substantial project-neutral core:

- architecture-normalized high-P-code export;
- direct-call normalization and callgraph extraction;
- receiver/type acquisition and conservative receiver inference;
- ARM32 Itanium primary-vtable slot export;
- function/instruction/P-code/address/reference/scalar/field-store evidence exporters;
- program metadata indexing;
- canonical P-code family mining;
- family-grouped selective classification;
- evidence-aware selective classification;
- accept-error routing;
- frozen validation and drift diagnostics;
- hash-pinned benchmark manifests, allowlisted smoke/full execution and metric-gate summaries;
- stable schemas under `schemas/`;
- generic runners under `scripts/`;
- project-neutral tests under `tests/`.

The main remaining gaps are not basic extraction. They are:

- standardized benchmark projections for classifier, router and receiver metrics;
- higher receiver/type coverage on hard unseen cases;
- better classifier operating points at the game/engine boundary;
- higher safe router coverage;
- a reusable semantic/effect representation;
- dependency-aware autonomous orchestration;
- stronger cross-project validation.

Reference measurements currently retained by the Nevergone consumer give the following planning baselines. They are consumer benchmark numbers, not hard-coded truths of this repository:

| KPI | Reference baseline | Next gate | Stretch |
| --- | ---: | ---: | ---: |
| Classifier macro-F1 | ~0.765 | >=0.80 | >=0.83 |
| `game` precision | ~0.42 broad / ~0.70 conservative | >=0.70 | >=0.75 |
| `game` recall | ~0.71 broad / ~0.52 conservative | >=0.65 | >=0.70 |
| Router accepted precision | ~0.974 | >=0.970 hard floor | >=0.975 |
| Router coverage | ~0.44 current / ~0.58 earlier nested | >=0.55 | >=0.65 |
| Exact vtable-slot mismatch | 0 on retained checks | 0 | 0 |
| Totally-unseen receiver evidence coverage | low-20% range | >=35% | >=50% |
| Semantic role macro-F1 | not canonical yet | >=0.75 | >=0.82 |
| Autonomous supported-task resolution | not canonical yet | >=65% | >=80% |
| Autonomous critical wrong-accept rate | not canonical yet | <2% | <1% |
| Non-Nevergone validated consumers | 1 early consumer (NFS Shift) | >=2 | >=3 |

## 3. Engineering rules

### 3.1 Evidence classes remain distinct

Every conclusion must retain whether it came from:

- exact static evidence;
- bounded runtime/native evidence supplied by a consumer;
- inferred structural evidence;
- learned/model prediction;
- human label/review;
- interventional probe.

Derived evidence must retain lineage so correlated signals are not counted as independent confirmation.

### 3.2 Project-neutral core only

`revenginstr` may encode architecture, ABI, compiler, Ghidra, P-code, object-layout, vtable, callgraph, statistical and generic semantic concepts. It must not embed title-specific addresses, class names, offsets or semantic rules.

### 3.3 Leakage-resistant ML

Generic model input must exclude raw function identities and project fingerprints unless an experiment explicitly declares itself non-transferable. Evaluation must remain family-isolated and use frozen unseen/cross-project holdouts.

### 3.4 Precision before coverage

Automatic `accept` decisions have a hard precision floor. Coverage may increase only while safety metrics remain above their gate.

### 3.5 Reproducible artifacts

Every major stage should be able to emit:

- input hashes/IDs;
- schema/tool/model/config versions;
- outputs and metrics;
- failure/reason codes;
- provenance references;
- enough information to reproduce the decision.

### 3.6 Fail closed

Ambiguous joins, unsupported architecture/patterns, evidence conflicts, OOD inputs and incompatible schema versions become `review`, `escalate` or explicit failure states.

---

# 4. Milestone map

| Milestone | Priority | Main result | Exit signal |
| --- | --- | --- | --- |
| M0 | P0 | Canonical benchmark and measurement layer | Clean checkout reproduces pinned smoke/full summaries |
| M1 | P0 | Evidence/schema consolidation | Generic shared exporters cover >=95% of reusable evidence paths |
| M2 | P0 | Receiver/type/vtable recovery v2 | >=35% unseen receiver coverage with zero exact-evidence regression |
| M3 | P0 | Classifier v6 | Better calibrated game/engine boundary |
| M4 | P0 | Router v9 | >=0.970 accepted precision and >=0.55 safe coverage |
| M5 | P1 | Semantic Effect IR | Evidence-linked behavior/role summaries |
| M6 | P1 | Autonomous analysis orchestrator | Bounded evidence acquisition and convergence |
| M7 | P1/P2 | Cross-project productization | Stable reusable pipeline across multiple consumers |

---

# 5. M0 — Canonical benchmark and measurement layer

## Goal

Make every later change measurable against one versioned evaluation contract.

## Work

### M0.1 Benchmark manifest

Add a project-neutral benchmark manifest format that pins:

- corpus/schema versions;
- consumer-provided dataset IDs/hashes;
- split/family identities;
- evidence artifact identities;
- classifier/router configs;
- expected metric names and gate policy.

The manifest identifies proprietary consumer inputs by hash/path contract; it does not embed them.

### M0.2 One-command benchmark runner

Add a runner that can execute, in dependency order:

1. schema/corpus validation;
2. evidence aggregation;
3. receiver inference evaluation;
4. classifier evaluation;
5. router evaluation;
6. semantic evaluation when M5 exists;
7. combined summary generation.

Support `smoke` and `full` modes.

The initial runner is available as `revenginstr-benchmark`. It validates pinned
input artifacts and schemas, runs allowlisted tools in dependency order without
a shell, and emits a versioned hash/runtime/metric-gate summary. Bounded
caller-argument-to-field-store graph construction and the initial
`FunctionEffectIR/1` projection are allowlisted stages.

### M0.3 Summary schema

Standardize a machine-readable result with at least:

- row counts and class distribution;
- per-class precision/recall/F1;
- macro-F1 and balanced accuracy;
- confusion matrix;
- coverage/abstention;
- calibration bins;
- receiver coverage;
- exact-evidence mismatch count;
- OOD/conflict/failure reason counts;
- runtime/memory/artifact size.

The summary now includes opt-in classifier/router, receiver and frozen/drift
validation projections. These provide class distributions and metrics,
confusion matrices, selective coverage, calibration bins, receiver status
coverage, exact-evidence comparison gates, configured reason-code counts,
artifact sizes, stage runtimes and platform-supported peak RSS. Exact comparison
keys and row values remain out of the summary. Unlabeled validation reports are
kept diagnostic and do not receive fabricated accuracy metrics.

### M0.4 Determinism audit

`revenginstr-determinism-audit` reruns the selected benchmark stages twice with
the same pinned inputs and isolated outputs. It compares stage results,
artifact hashes (including row selection and predictions), metrics, projections
and benchmark manifests, while excluding runtime and peak RSS. A versioned
JSON report lists the differing paths and per-run artifact/metric hashes.

### M0.5 CI policy

- ✅ per-PR unit/schema/synthetic smoke;
- ✅ generic exporter contract/boundary checks in CI;
- ✅ migration PRs require exporter parity fixtures in that CI suite;
- ✅ manual/scheduled heavier frozen benchmark entry point in consumer repos;
- ✅ machine-readable metric deltas for behavior-changing PRs.

The repository CI runs the full unit/schema/synthetic suite and generic exporter
boundary checks on every PR; exporter migration PRs must include their parity
fixtures in that suite. A reusable consumer benchmark workflow supports manual
or scheduled frozen runs in the consumer repository, where manifests, labels
and summaries remain owned. The benchmark delta command compares retained
baseline and candidate summaries for attachment to behavior-changing PRs.

## Exit criteria

- Clean checkout reproduces the canonical smoke benchmark.
- Full benchmark emits a pinned summary bundle.
- Every ML metric bundle contains dataset/split/model identity.
- Deterministic stages reproduce bit-for-bit or document bounded nondeterminism.
- Schema mismatch fails closed.

---

# 6. M1 — Evidence and schema consolidation

## Goal

Finish the extraction of generic analysis logic into `revenginstr` and remove duplicated consumer implementations.

## Work

### M1.1 Exporter inventory

**Initial inventory complete (2026-10-17):** see
[`docs/EXPORTER_INVENTORY.md`](EXPORTER_INVENTORY.md). It classifies the
reusable exporter surface using the `origin/main` snapshots of all three
repositories and records compatibility wrappers, remaining duplicate
implementations, consumer-specific tooling, and the evidence required before
retiring any fallback. Consumer working trees were left unchanged. Keep the
inventory current as each exporter is migrated.

Maintain an inventory of reusable exporters/runners classified as:

- canonical in `revenginstr`;
- canonical with thin consumer compatibility wrapper;
- consumer-specific by design;
- duplicate pending migration;
- obsolete.

### M1.2 Stable schema contracts

**Complete (2026-10-17):**
[`docs/SCHEMA_CONTRACTS.md`](SCHEMA_CONTRACTS.md) defines the shared versioning,
wire, provenance, ordering, failure, and compatibility rules and indexes every
schema currently published in `schemas/`. Closed schemas now cover the five
legacy Program Index TSV tables and ARM32 vtable-slot TSV without changing
exporter output. The index also covers P-code audit, foreign-guard,
receiver-plan, function-family, selective classifier, evidence-aware
classifier, and accept-error-router manifests and prediction records. Tests
validate generated model, OOF, inference, and router artifacts against those
contracts.

For every stable evidence family document:

- format/version;
- required/optional fields;
- normalization rules;
- provenance fields;
- ordering guarantees;
- failure behavior;
- compatibility policy.

### M1.3 Synthetic/parity fixtures

Every migrated exporter gets a legal synthetic or minimal fixture so parity can be tested without redistributing game binaries.

**Initial fixtures added (2026-10-17):** a synthetic P-code corpus record,
Function/Bounded P-code TSV row, and decoded payloads for all five Program
Index tables and ARM32 Itanium vtable slots. Tests run P-code records through
audit/schema validation and check exact TSV headers, column ordering, and rows
against their v1 schemas. `revenginstr-export-parity` compares two UTF-8 TSV
outputs in row order and emits hashes/counts plus the first mismatch without
retaining record values. Nevergone now records byte-identical bounded forward
and reverse outputs on one root and a forward output on a second root from the
same analyzed program under equivalent priority rules. The [report and
invocation details](https://github.com/Hanz0Hatt0r1/nevergone-recomp/blob/main/docs/evidence/ghidra-export-parity.md)
stay in that consumer. Expand reverse coverage and additional bounds before
retiring the local fallbacks. The work remains open for fixtures accompanying
later exporter migrations.
The synthetic address-reference-owner TSV fixture now covers a resolved
reference and the no-reference sentinel row against its v1 schema.
The synthetic High-P-code flow fixture now includes complete load-to-return and
call-result-to-return sequences; these drive the generic dataflow tests and are
validated operation-by-operation against the shared row schema.
Paired caller-argument subtree and exact formal-root TSV fixtures now exercise
recursive argument propagation and validate both exporter row schemas.
Paired synthetic parameter-to-field store/load TSV fixtures now match the
exporter's emitted headers column-for-column and validate every row against
their published schemas.
The defined-string exporter now has a synthetic TSV fixture that checks its
wire header, schema rows, canonical Base64 decoding, and Java UTF-16 length
accounting, including a non-BMP character.
Synthetic function-identity plan/output TSVs now cover exact and containing
resolution requests, preserve their plan keys, and validate both wire headers
and row schemas.
Function-instruction and address-slice contract tests now consume persisted
synthetic JSON fixtures with nested instruction/P-code rows, while retaining
the existing empty/not-found cases as boundary checks.

### M1.4 Consumer boundary

Consumers may own path discovery, proprietary joins, old-command compatibility and title-specific postprocessing. Generic parsing/recovery logic belongs here.

### M1.5 Performance baselines

Record representative wall time, peak memory and output size for whole-program exporters.

## Exit criteria

- >=95% of reusable evidence extraction in active consumers comes from shared primitives or thin wrappers.
- Every migrated exporter has parity coverage.
- Generic evidence formats have explicit version/provenance contracts.
- No unexplained output drift between shared and compatibility paths.

---

# 7. M2 — Receiver/type/vtable recovery v2

## Goal

Increase hard unseen receiver coverage without weakening exact evidence safety.

## Work

### M2.1 Residual failure taxonomy

The receiver inference CLI can emit a
[`ReceiverFailureReason/1`](RECEIVER_FAILURE_REASONS.md) sidecar with exactly
one stable primary code for each unresolved row. It leaves the existing
`ReceiverInference/1` output and schema unchanged. Current type/catalog evidence
supports `receiver_not_single_pointer`, `insufficient_receiver_type_evidence`,
`missing_vtable_catalog_entry`, `mixed_receiver_candidates`, and
`ambiguous_receiver_vtable`. The sidecar schema reserves the remaining
provenance and dataflow codes below; they are emitted only when the
corresponding evidence is available, not inferred from missing type names.

Every unresolved receiver query receives one stable primary reason, including:

- missing root provenance;
- ambiguous PHI/MULTIEQUAL;
- caller-argument propagation gap;
- field load/store propagation gap;
- singleton/default-instance gap;
- factory-return gap;
- nested/container object gap;
- mixed receiver candidates;
- missing vtable catalog entry;
- slot ambiguity;
- non-virtual `CALLIND`;
- linker/veneer artifact;
- P-code/decompiler limitation;
- unsupported pattern.

### M2.2 Receiver provenance graph

**Graph contract v1 and receiver-anchor projection implemented:** [`ReceiverProvenanceGraph/1`](../schemas/receiver-provenance-graph-v1.schema.json) defines graph-local ids, the generic receiver-flow node/relation vocabulary, evidence classes, and source-record provenance. The generic validator rejects duplicate ids and dangling endpoints. `revenginstr-receiver-graph` projects typed receiver TSV rows with an observed receiver operand into receiver-to-call graphs, retaining source-record provenance and rejecting invalid joins/formats. The schema and synthetic contract test contain no consumer labels, addresses, or catalogs.

`revenginstr-receiver-argument-store-flow` now joins bounded caller roots to
parameter-store rows only on exact callee/function entry and formal parameter
index. Both source rows remain explicit on their respective edges. The
parameter-store exporter can emit explicit parameter-rooted `LOAD` evidence;
`revenginstr-receiver-argument-load-flow` joins caller roots to those loads on
the same exact function/parameter keys. No names, offsets, or inferred
receiver types are fallback joins.

### M2.3 Bounded interprocedural propagation

**Bounded caller-argument, field-store, field-load, and return anchors implemented:** `revenginstr-receiver-argument-flow` projects bounded subtree roots into actual-argument-to-formal-parameter edges and captures generic call-result producers when explicit in P-code; `revenginstr-receiver-store-flow` projects parameter-to-field-store evidence into destination and stored-value edges. `revenginstr-receiver-argument-store-flow` and `revenginstr-receiver-argument-load-flow` join those artifacts by exact function/parameter keys with provenance from both inputs. `revenginstr-receiver-field-access-pairs` groups same-function stores and loads only when formal parameter and numeric field offset match. `revenginstr-receiver-load-return-flow` traces parameter-rooted loads through P-code def-use chains to `RETURN` operations without assigning getter semantics; `revenginstr-receiver-call-return-flow` traces call-result values through P-code to function returns as a generic factory-return anchor, without assigning factory semantics. The caller-argument exporter can optionally emit direct caller-formal roots; `revenginstr-receiver-argument-propagate` walks those exact links backward under depth and edge caps. Store-to-load value-flow checks remain open.

Remaining propagation work:

1. consumer-validated factory hypotheses linked to call-result-to-return paths;
2. consumer-validated getter/accessor hypotheses from load-to-return evidence;
3. establish instruction order and reaching-definition/path compatibility before treating paired field stores and loads as value flow;
4. constructor/vtable anchors.

### M2.4 Ambiguity handling

**Optional assessment sidecar implemented:** `ReceiverCandidateAssessment/1` distinguishes same-type convergence, consumer-declared compatible subtype candidates, mixed candidates, partially unknown candidates, and no known candidates. It retains all ambiguous terminal-name candidates and leaves `ReceiverInference/1`, routing, and transfer permissions unchanged. Consumer catalogs supply compatibility groups; absent or conflicting groups fail toward `mixed_candidates`.

### M2.5 Candidate scoring

**Evidence vector schema and benchmark projection implemented:** `ReceiverCandidateEvidence/1` exposes exact vtable, constructor/factory, field/layout, slot, caller, callgraph, and runtime witness dimensions as separate states with provenance. Frozen benchmark summaries can count states and evidence classes per dimension without combining correlated evidence; the contract still defines no aggregate score or decision. Consumers retain candidate identities and evidence.

### M2.6 Frozen receiver benchmark

Provide a reusable receiver evaluation harness that consumers can populate with sealed unseen cases.

The generic benchmark runner projects `ReceiverCandidateAssessment/1`
sidecars into status counts, candidate-count distributions, unknown-candidate
counts, and compatibility-group row counts. It also summarizes the separate
dimensions in `ReceiverCandidateEvidence/1`. Consumers can combine these
projections with exact-evidence gates against sealed expected outputs; only
aggregate metrics enter shared summaries. This completes the reusable harness
contract, while coverage and exact-evidence exit targets still require
consumer-owned frozen datasets and results.

## Exit criteria

Near-term:

- >=35% useful receiver evidence coverage on a frozen unseen benchmark;
- zero mismatches on exact vtable/runtime hard gates;
- >=30% relative reduction in unsupported/unknown residuals without false confident convergence;
- every unresolved row has an auditable reason code.

Stretch: >=50% useful unseen coverage with no material rise in mixed-receiver false convergence.

---

# 8. M3 — Classifier v6

## Goal

Improve classification while keeping transferability, calibration and leakage resistance.

Family-grouped classwise correctness calibration and routing thresholds are
already learned during training. `revenginstr-selective-threshold-sweep` now
adds an audit-only per-class precision/coverage sweep over the exact OOF files
and manifest, with both input hashes retained; it does not modify routing.
`revenginstr-selective-threshold-evaluate` applies those OOF-selected thresholds
to a separate family-disjoint evaluation population and records per-class
reliability bins, Brier score, ECE, and held-out precision/coverage.
`revenginstr-classifier-error-buckets` groups errors from that exact evaluation
population by confusion pair and route action, retaining aggregate confidence
and family counts without exporting row identities.
`revenginstr-selective-subgroup-audit` joins a caller-owned subgroup sidecar to
the exact hash-pinned evaluation population and reports aggregate accuracy,
calibration, route coverage, and class counts without exporting ids. The tool
does not assign ID/OOD semantics; callers define subgroup names and membership.
`revenginstr-classifier-ablation-audit` compares caller-produced P-code-only
and evidence-aware family-grouped OOF runs when they share the same seed,
folds, dataset fingerprint, ids, families, and labels. It reports paired error
changes and aggregate per-class/routing deltas without exporting identities;
the caller remains responsible for actually removing the named feature group.
`revenginstr-retain-hard-negatives` can write a consumer-owned review artifact
from confidence/action-filtered errors in the exact family-disjoint evaluation
set. It retains selected ids and labels only in that caller-directed artifact;
it does not alter datasets or inject examples into later training.

## Work

- consumer-run ablations for P-code, callgraph, receiver, field, external-call and family features, compared with the paired OOF audit;
- coarse Effect-IR features once M5 begins;

Subgroup metrics are available for caller-defined partitions. Establishing ID
or OOD membership remains a dataset/evaluation responsibility and is not
inferred by the generic audit.

Audit-only identities may be used to understand errors but must not silently enter generic model input.

## Exit criteria

Near-term frozen-family targets:

- macro-F1 >=0.80;
- `game` precision >=0.70;
- `game` recall >=0.65;
- no unexplained >2 percentage-point regression in another major class;
- reproducible calibrated confidence for routing.

Stretch: macro-F1 >=0.83, game precision >=0.75, game recall >=0.70.

---

# 9. M4 — Selective router v9

## Goal

Safely automate more decisions than classifier confidence alone can support.

## Inputs

The router should combine independent signals such as:

- calibrated classifier confidence/margin/entropy;
- OOD/family distance;
- receiver evidence quality;
- callgraph support;
- cross-model agreement;
- evidence conflicts;
- known failure bucket membership.

## Required behavior

- per-class acceptance policies;
- hierarchical acceptance (coarse answer accepted while finer answer is reviewed);
- conflict quarantine;
- coverage decomposition by class, ID/OOD and evidence availability;
- reason codes for every route;
- a frozen routing gate not used for threshold tuning.

## Exit criteria

Hard gate:

- accepted precision >=0.970;
- coverage >=0.55;
- critical false-accept rate <1%;
- detected evidence conflicts never route to `accept`.

Stretch: precision >=0.975 and coverage >=0.65.

---

# 10. M5 — Semantic Effect IR

## Goal

Move from structural/domain classification to auditable behavioral understanding.

## M5.1 Effect IR schema

**Initial `FunctionEffectIR/1` projection implemented:** the generic CLI groups
parameter-rooted field reads/writes and P-code direct/indirect call and return
operations by function and is available as a pinned benchmark stage. Each fact
retains exact source-artifact hashes and record ordinals; read/write facts
remain `derived_structural`, and call/return operations remain `exact_static`.
This version assigns no roles or API categories and makes no store-to-load
reachability claim. Other effect classes remain open for separately evidenced
additions.

Define a normalized function-level representation containing evidence-backed facts about:

### Memory/object effects

- parameter-derived field reads/writes;
- global reads/writes;
- candidate offsets/widths;
- block copy/clear;
- allocation/free/refcount-like behavior.

### Call effects

- internal/external and direct/indirect calls;
- API categories;
- callback registration/invocation;
- factory/getter/setter-like patterns;
- caller/callee neighborhood summaries.

### Control effects

- loops;
- branch shape;
- switch/state-machine patterns;
- validation/fail paths;
- retry/poll/update behavior.

### Data effects

- parser/decoder-like reads;
- serializer-like writes;
- hashing/comparison;
- lookup/indexing;
- math/coordinate transforms;
- container iteration.

### Type context

- receiver candidates;
- vtable/slot evidence;
- constructor/destructor relationship;
- layout compatibility;
- neighboring methods sharing object evidence.

Each field retains evidence lineage.

## M5.2 Semantic role taxonomy

**Initial generic taxonomy and contracts implemented:**
[`SemanticRoleLabel/1`](../schemas/semantic-role-label-v1.schema.json) accepts
adjudicated consumer-owned multi-label rows, and
[`SemanticRolePrediction/1`](../schemas/semantic-role-prediction-v1.schema.json)
uses the same bounded role keys. The schema carries opaque row/family/dataset
identities only; no consumer labels or data are stored here.

Initial roles should remain bounded and multi-label-capable:

- lifecycle/init/shutdown;
- accessor/getter/setter;
- constructor/destructor/factory;
- parser/decoder/loader;
- serializer/save writer;
- state update/tick;
- input handler;
- render submission;
- animation/action update;
- physics/collision query;
- combat/state transition;
- resource lookup/cache;
- callback/scheduler adapter;
- network/media/runtime adapter;
- utility/container/math;
- unknown/compound.

## M5.3 Structured summaries

Generate a machine-readable summary first. Natural-language rendering may only restate claims present in that object.

## M5.4 State-machine recovery

Recover candidate state fields and transition graphs from repeated comparisons/writes, switch structure and cross-function field sharing, with confidence per edge.

## M5.5 Object-role clustering

Cluster methods using receiver, field, vtable, callgraph and Effect-IR similarity.

## M5.6 Evaluation contract

**Paired evaluator v1 implemented:** `revenginstr-semantic-role-evaluate`
requires exact function ids and matching family/dataset/split identities, and
reports aggregate per-role, micro/macro-F1, and exact-match metrics. It can
verify function-id and family disjointness against a caller-supplied
training-family artifact; without that artifact it explicitly reports
`not_checked`. Frozen consumer gold sets and the >=500-row target remain open.

Provide a generic semantic-label schema. First consumer gold set target: >=500 functions, growing toward 1,000+ across projects.

## Exit criteria

- stable Effect IR schema;
- role macro-F1 >=0.75 on a family-isolated consumer holdout;
- >=90% audit acceptance for high-confidence structured summaries;
- unsupported factual claims <5% in the high-confidence bucket;
- every high-confidence claim linked to machine-readable evidence.

Stretch: role macro-F1 >=0.82 and >=95% summary acceptance.

---

# 11. M6 — Autonomous analysis orchestrator

## Goal

Turn independent analyzers into a bounded iterative system that acquires the next useful evidence, invalidates dependent artifacts and converges or escalates.

## Work

### M6.1 Task graph

Explicit dependencies, for example:

`P-code -> callgraph -> receiver provenance -> vtable/slot -> Effect IR -> classifier -> semantic role -> router`.

### M6.2 Evidence request planner

For unresolved/high-value functions choose only from reviewed bounded actions, such as:

- deeper P-code/function slice;
- callers/callees;
- field-store recovery;
- constructor/vtable anchors;
- consumer-provided bounded native probe;
- neighboring family examples;
- human review.

The planner must never synthesize arbitrary executable probes on its own.

### M6.3 Convergence states

Standardize terminal states:

- `accepted_exact`;
- `accepted_high_confidence`;
- `review_required`;
- `escalated_conflict`;
- `unsupported`;
- `budget_exhausted`.

### M6.4 Decision ledger

Persist previous state, new state, evidence added, responsible rule/model, confidence delta and artifact references.

### M6.5 Human feedback

Generic feedback schema: confirmed, rejected, partially correct, ambiguous, needs-more-evidence. Feedback retains reviewer/provenance quality and does not automatically become training truth.

### M6.6 Cost-aware prioritization

Prioritize by downstream leverage, unresolved dispatches, graph centrality and expected uncertainty reduction.

## Exit criteria

First target on supported frozen tasks:

- >=65% automatic resolution;
- critical wrong-accept rate <2%;
- >=50% reduction in human-review workload versus classifier-only triage;
- deterministic decision ledger for every automatic resolution;
- conflicts/OOD fail closed.

Stretch: >=80% resolution, <1% critical wrong accepts and bounded convergence for >=95% of evaluated tasks.

---

# 12. M7 — Cross-project validation and productization

## Goal

Prove that `revenginstr` is generic rather than shaped around one consumer.

## Work

### M7.1 Cross-project matrix

Validate on at least two additional binaries/projects varying compiler, symbols, engine/framework, optimization level, size and architecture where supported.

### M7.2 Zero-semantic-adaptation run

Run without title-specific semantic rules and record extraction success, receiver coverage, model/router behavior and semantic-summary audit quality.

### M7.3 Adapter accounting

Every consumer adapter is explicitly classified as:

- path/input adapter;
- schema conversion;
- ABI/architecture adapter;
- evidence source adapter;
- semantic/domain rule.

The count and complexity of semantic/domain rules is a generalization KPI.

### M7.4 Distribution-shift report

Detect drift in P-code features, size buckets, API categories, receiver evidence, calibration/confidence and family/OOD distance.

### M7.5 Stable interfaces

Define supported entry points for:

- evidence extraction;
- benchmark execution;
- receiver inference;
- classification/routing;
- semantic analysis;
- orchestration;
- result/report generation.

### M7.6 Documentation

Provide install, Ghidra setup, first-analysis, schema, benchmark, adapter, confidence/evidence and failure-triage guides.

## Exit criteria

- generic pipeline validated on >=2 non-Nevergone targets;
- no hidden Nevergone identity feature is required;
- distribution shift is explicitly reported rather than silently trusted;
- a new consumer can produce its first evidence + triage report through documented commands.

---

# 13. Evaluation and CI matrix

| Test layer | Purpose | Required for |
| --- | --- | --- |
| Unit tests | parser/scorer/schema correctness | every logic change |
| Synthetic Ghidra fixtures | exact behavior without proprietary inputs | exporter/recovery changes |
| Exporter parity | shared vs compatibility output | migrations |
| Consumer smoke | prevent downstream regressions | integration changes |
| Family-grouped evaluation | prevent structural duplicate leakage | ML changes |
| Frozen unseen benchmark | real generalization | receiver/classifier/router changes |
| Exact receiver/vtable fixtures | safety hard gate | receiver changes |
| Calibration/OOD evaluation | safe automation | classifier/router changes |
| Semantic audit set | role/claim quality | M5+ |
| Cross-project holdout | transfer | M7/release |
| Determinism test | reproducibility | releases |
| Performance benchmark | scalability | exporter/orchestrator changes |

A behavior-changing PR should include before/after metrics or a pointer to the retained full benchmark artifact when the heavy benchmark is not suitable for PR CI.

---

# 14. Data and label strategy

1. Keep source names, addresses, raw strings and title-local IDs in audit/trace artifacts unless a declared experiment intentionally studies them.
2. Preserve evidence quality tiers with machine-readable reason codes.
3. Do not manufacture negatives: unknown is not automatically `other`, `engine` or non-game.
4. Prioritize manual evidence work on high-disagreement, high-centrality and repeated-family cases.
5. Once a frozen set materially influences a new rule/threshold, retire it as the final untouched test and create a new sealed holdout.

---

# 15. PR-sized implementation sequence

## P0 — immediate

1. ✅ Canonical benchmark manifest schema.
2. ✅ One-command benchmark runner.
3. ✅ Standardized combined metric projections for classifier, receiver, router and validation reports.
4. Exporter/schema inventory.
5. Receiver residual taxonomy v1.
6. Frozen receiver coverage report.
7. Classifier threshold/calibration sweep tooling.
8. Classifier error-cluster report.
9. Router evidence-aware reason codes and scoring inputs.
10. Frozen router >=0.970 precision / >=0.55 coverage gate.
11. Markdown + JSON KPI dashboard artifact.

## P1 — after measurement is stable

12. ✅ Receiver provenance graph IR schema and reference validator; graph construction is still open.
13. Interprocedural receiver propagation v1 (bounded caller-argument and field-store anchors plus exact one-hop joins landed; recursive propagation and store/load joins remain open).
14. ✅ Initial Effect IR schema + structural extractor v1; additional effect classes and semantic evaluation remain open.
15. ✅ Initial generic semantic-label/evaluation format and paired scorer; family-isolated consumer gold sets remain open.
16. Structured function summary v1.
17. Semantic role baseline.
18. State-machine candidate detector.
19. Object-role clustering.
20. Analysis task graph/invalidation model.
21. Decision ledger and convergence states.

## P2 — autonomy and transfer

22. Bounded evidence request planner.
23. Human review feedback format.
24. Cross-project holdout harness.
25. Distribution-shift report.
26. Stable top-level analysis CLI/result schema.
27. Release-grade documentation and compatibility policy.

---

# 16. Recommended execution order

### Wave A — measurement and safety

M0 plus the highest-value M1 cleanup. No major semantic work should land without a benchmark capable of proving whether it helped.

### Wave B — structural coverage

M2: residual taxonomy, provenance graph, bounded interprocedural propagation, >=35% unseen receiver coverage, zero exact-evidence mismatches.

### Wave C — classifier/router operating point

M3 + M4: calibrated classifier and router >=0.970 precision / >=0.55 coverage.

At the end of Wave C, `revenginstr` should qualify as a mature assisted reverse-engineering analysis core.

### Wave D — semantic understanding

M5: Effect IR, semantic gold/evaluation sets in consumers, structured summaries, roles, state/object recovery.

### Wave E — autonomy

M6: task graph, evidence planner, decision ledger, bounded convergence and >=65% automatic resolution on supported frozen tasks.

### Wave F — transfer/productization

M7: multiple independent consumers, drift handling, stable interfaces, project-adapter guide and release benchmark workflow.

---

# 17. Definition of done

A `revenginstr` analysis feature is complete only when:

1. input/output schema is explicit;
2. evidence provenance is retained;
3. unsupported inputs fail closed;
4. unit/smoke coverage exists;
5. relevant frozen evaluation shows no unacceptable regression;
6. before/after metrics are retained when behavior changes;
7. deterministic behavior is verified where expected;
8. reproduction documentation exists;
9. generic logic contains no unnecessary consumer-specific assumptions;
10. downstream consumers can distinguish exact, inferred and learned evidence.

---

# 18. Major risks

### Overfitting the toolchain to Nevergone

Mitigation: project-neutral schemas, cross-project frozen tests, explicit adapters, early zero-semantic-adaptation runs.

### Metric chasing against one frozen set

Mitigation: retire contaminated holdouts and create new sealed tests; retain family and cross-project isolation.

### Coverage pressure causes false accepts

Mitigation: hard router precision floor, OOD/conflict quarantine, subgroup metrics and abstention-first policy.

### Correlated evidence is treated as independent confirmation

Mitigation: evidence lineage and common-upstream tracking.

### Semantic labels become subjective

Mitigation: structured effects/roles, ambiguity flags, reviewer agreement sampling and real `unknown/compound` states.

### Schema migration breaks consumers

Mitigation: versioned schemas, compatibility readers where justified, fixtures and fail-closed version checks.

### Orchestration amplifies an early wrong hypothesis

Mitigation: immutable decision ledger, evidence-class precedence, confidence caps and bounded passes.

### Larger models hide structural weaknesses

Mitigation: preserve heuristic/sparse baselines, feature ablations and evidence-linked structured outputs.

---

# 19. Success states

## Assisted-analysis milestone

- exact structural evidence remains regression-free;
- unseen receiver coverage >=35%;
- classifier macro-F1 >=0.80 with game precision >=0.70 and recall >=0.65 on an appropriate consumer benchmark;
- router precision >=0.970 and coverage >=0.55;
- accepted decisions are reproducible and provenance-linked.

## Semantic-analysis milestone

- stable Effect IR;
- >=500 evidence-backed semantic functions across consumers;
- semantic role macro-F1 >=0.75;
- >=90% acceptance of high-confidence structured summaries;
- state/object recovery validated across multiple independently understood subsystems.

## Autonomous-analysis milestone

- >=65% of supported frozen tasks resolve automatically;
- critical wrong accepts <2%;
- conflicts reliably escalate;
- full evidence/decision chain is replayable;
- at least two non-Nevergone consumers have measured transfer behavior.

---

# 20. Immediate next action

Continue with **M1.3**: expand synthetic/parity fixtures as shared exporter
verticals migrate, keeping game binaries and labels consumer-owned. Keep the
schema registry and generated-artifact checks current in every format change.
The benchmark and CI policy milestones now have shared schemas, replay checks
and consumer-owned report retention.
