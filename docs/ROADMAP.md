# revenginstr Development Roadmap

**Status:** active engineering plan  
**Baseline:** 2026-10-18, `main` through `2e03135b324e684b1d78900782d33005f802d381`
**Scope:** project-neutral reverse-engineering analysis infrastructure: evidence extraction, indirect-dispatch recovery, receiver/type/vtable inference, ML classification, selective routing, semantic inference, orchestration, validation, whole-program type/layout recovery, bounded hybrid static/dynamic analysis, semantic program graphs, feedback-driven learning, architecture/ABI expansion, decompiler/recompiler integration, and reusable interfaces.

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
9. machine-readable artifacts consumable by decompilation/recompilation projects;
10. a whole-program recovered model of function signatures, object layouts, ownership/lifetime and type relationships where evidence supports them;
11. a provenance-linked semantic program graph connecting functions, objects, fields, states, resources, callbacks and execution contexts;
12. optional reversible suggestion bundles that can safely project accepted analysis back into decompiler and recompilation workflows.

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
- stronger cross-project validation;
- whole-program signature, type and object-layout recovery;
- bounded static/dynamic evidence acquisition for cases static analysis cannot resolve;
- a unified semantic program graph above per-function summaries;
- a leakage-safe reviewer-feedback-to-training loop;
- architecture/ABI expansion beyond the initial ARM32/x86-32 consumers;
- safe decompiler/recompiler apply-back of accepted results.

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
| High-confidence recovered-layout audit acceptance | not canonical yet | >=90% | >=95% |
| Decisive bounded probe rate on planner-selected unresolved cases | not canonical yet | >=50% | >=70% |
| Semantic graph accepted-edge precision | not canonical yet | >=0.95 | >=0.98 |
| Validated ISA/ABI combinations | ARM32 + early x86-32 consumers | >=4 | >=5 |

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
| M8 | P1 | Whole-program type/layout recovery | Evidence-backed signatures, object layouts and lifetime relationships |
| M9 | P1 | Hybrid static/dynamic analysis | Bounded probes resolve high-value static ambiguities with provenance |
| M10 | P1 | Semantic Program Graph | Unified evidence-linked model of program entities and relationships |
| M11 | P1/P2 | Active learning and feedback loop | Reviewed feedback can improve models without contaminating evaluation |
| M12 | P2 | Architecture/ABI expansion | Shared core validated across ARM64, x86-64 and PowerPC-class targets |
| M13 | P2 | Decompiler/recompiler integration | Accepted results can be safely projected back into analysis workflows |

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
caller-argument-to-field-store graph construction, the initial
`FunctionEffectIR/1`, `FunctionSummary/1`, decision-ledger audit, and bounded
field-store/load CFG path audit are allowlisted stages.

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

**Inventory refreshed (2026-10-18):** see
[`docs/EXPORTER_INVENTORY.md`](EXPORTER_INVENTORY.md). It classifies the
reusable exporter surface using current `origin/main` snapshots of all three
repositories and records compatibility wrappers, remaining duplicate
implementations, consumer-specific tooling, and the evidence required before
retiring any fallback. NFS Shift now has one same-input parity fixture for each
of its five shared-first exporter formats; the compatibility fallbacks remain
while callers are reviewed. A regression test keeps all `ghidra/*.java`
exporters listed. Keep the inventory current as each exporter is migrated.

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
outputs in row order; `revenginstr-jsonl-export-parity` does the same for
JSONL object records while ignoring object-key order and streams `.jsonl.gz`
inputs. Both emit hashes/counts plus the first mismatch without retaining
record values. Nevergone now records byte-identical bounded forward and reverse
outputs on one root and a forward output on a second root from the same
analyzed program under equivalent priority rules. The [report and invocation
details](https://github.com/Hanz0Hatt0r1/nevergone-recomp/blob/main/docs/evidence/ghidra-export-parity.md)
stay in that consumer. NFS Shift PRs [#2076](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2076),
[#2077](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2077), and
[#2078](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2078)
cover one query for each of five shared-first formats. The compact gzip
exports have equal ordered JSON records after decompression and key
normalization, but their compressed bytes differ. Keep fallbacks pending caller
review; targeted function parity does not cover all-functions mode. Expand
reverse coverage and additional bounds before retiring Nevergone's local
fallbacks. The work remains open for fixtures accompanying later migrations.
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
The synthetic High-P-code CFG fixture pins program/function identity,
operation sequence locations, and branch successors; the field-store/load
path-audit test exercises safe and effect-blocked routes without making a
memory reaching-definition claim.
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

**Program-wide indirect-call acquisition inventory implemented:**
[`CallindInventory/1`](CALLIND_INVENTORY.md) joins exact High-P-code flow rows
to bounded target expressions and reconciles them against a hash-linked
function population. The read-only batch exporter preserves per-function
completion, failure, and no-P-code states. On the frozen Nevergone unseen500
holdout, all 500 flow exports completed and all 203 observed `CALLIND` sites
matched the canonical P-code counts. The 24 canonical model text truncations
remain marked separately; 140 target expressions are depth-limited. All 203
sites remain `unknown` because this unlabeled holdout does not support accuracy
or recall claims for virtual dispatch. See the [hash-pinned consumer replay PR](https://github.com/Hanz0Hatt0r1/nevergone-recomp/pull/735).

### Evidence-first Phase B: bounded pointer provenance

This implements the next step in the
[evidence-first analysis strategy](https://github.com/Hanz0Hatt0r1/revenginstr/blob/main/docs/EVIDENCE_FIRST_ANALYSIS_STRATEGY.md).
[`PointerProvenance/1`](POINTER_PROVENANCE.md) follows exact High-P-code
def-use tokens through width-preserving `COPY`/`CAST`, constant `PTRADD`,
`PTRSUB`, `INT_ADD`/`INT_SUB`, and bounded `MULTIEQUAL` alternatives. Caller
formal roots are joined only from exact `GhidraCallerArgumentParameterRoot/1`
or `/2` keys. `LOAD` creates a memory-read anchor with a separate address
expression; calls, side-effect-dependent `INDIRECT`, dynamic offsets, cycles,
width mismatches, and unsupported operations remain explicit barriers or
abstentions.

The synthetic contract tests cover positive and negative offsets, dynamic
indices, distinct PHI roots, cycles, depth and alternative budgets, overflow,
width mismatch, exact call-root joins, and unrooted loads. Full suite: 511
passed with the repository's test and ML extras enabled.

On the pinned Nevergone unseen500-v10 replay, all 40,519 High-P-code rows from
500 functions were analyzed and all 203 `CALLIND` targets joined by exact
function/address/time and target-definition keys. The target provenance rows
are 191 `memory_read_anchor`, one constant `address_anchor`, two ambiguous,
eight side-effect barriers, and one unknown. The baseline inventory still
classifies all 203 sites as `unknown`; these structural facts make no
class/vtable identity, virtual-dispatch accuracy, or recall claim. See the
[hash-pinned PointerProvenance consumer replay](https://github.com/Hanz0Hatt0r1/nevergone-recomp/pull/736).

### M2.1 Residual failure taxonomy

The receiver inference CLI can emit a
[`ReceiverFailureReason/1`](RECEIVER_FAILURE_REASONS.md) sidecar with exactly
one stable primary code for each unresolved row. It leaves the existing
`ReceiverInference/1` output and schema unchanged. Current type/catalog evidence
supports `receiver_not_single_pointer`, `insufficient_receiver_type_evidence`,
`missing_vtable_catalog_entry`, `mixed_receiver_candidates`, and
`ambiguous_receiver_vtable`. It emits `ambiguous_phi` only when a
`GhidraIndirectReceiverType/1` row explicitly identifies an immediate
`MULTIEQUAL` definition and two distinct transparent-flow type names resolve
unambiguously to different catalog classes. It emits `non_virtual_call_indirect` only when a
`GhidraIndirectReceiverType/1` row explicitly records `receiver_present=0`,
and `unsupported_pattern` only when that format has no usable type and its
immediate receiver definition is outside the transparent P-code operations
followed by inference. The legacy inference status and output remain unchanged.
The sidecar schema reserves the other provenance and dataflow codes below;
they are emitted only when the corresponding evidence is available, not
inferred from missing type names.

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

`GhidraPointerTableSlots/1` now exports bounded caller-selected pointer tables
without assuming an ABI or vtable role. Each slot records raw bytes, decoded
pointer value, mapped target address, exact function-entry metadata when
available, and an explicit unmapped/unreadable/null state. A SHIFT replay
captures two tables and confirms the manually reviewed slots; it does not bind
either table to arbitrary receiver values or a call site.

`IndirectCallPointerSlot/1` joins exact `CALLIND` evidence to the matching
`PointerProvenance/1` load definition and reports a pointer-slot candidate only
when one resolved anchor, constant byte offset, and matching pointer width are
present. It exposes a reusable boundary for caller-selected table scans while
leaving vtable identity, receiver binding, and target resolution to additional
evidence.

`revenginstr-receiver-argument-store-flow` now joins bounded caller roots to
parameter-store rows only on exact callee/function entry and formal parameter
index. Both source rows remain explicit on their respective edges. The
parameter-store exporter can emit explicit parameter-rooted `LOAD` evidence;
`revenginstr-receiver-argument-load-flow` joins caller roots to those loads on
the same exact function/parameter keys. No names, offsets, or inferred
receiver types are fallback joins.

### M2.3 Bounded interprocedural propagation

**Bounded caller-argument, field-store, field-load, and return anchors implemented:** `revenginstr-receiver-argument-flow` projects bounded subtree roots into actual-argument-to-formal-parameter edges and captures generic call-result producers when explicit in P-code; `revenginstr-receiver-store-flow` projects parameter-to-field-store evidence into destination and stored-value edges. `revenginstr-receiver-argument-store-flow` and `revenginstr-receiver-argument-load-flow` join those artifacts by exact function/parameter keys with provenance from both inputs. `revenginstr-receiver-field-access-pairs` groups same-function stores and loads only when formal parameter and numeric field offset match. `revenginstr-receiver-load-return-flow` traces parameter-rooted loads through P-code def-use chains to `RETURN` operations without assigning getter semantics; `revenginstr-receiver-call-return-flow` traces call-result values through P-code to function returns as a generic factory-return anchor, without assigning factory semantics. The caller-argument exporter can optionally emit direct caller-formal roots; `revenginstr-receiver-argument-propagate` walks those exact links backward under depth and edge caps. `revenginstr-receiver-field-store-load-audit` now joins parameter/offset-compatible pairs to a program-pinned High-P-code CFG and reports bounded paths with no explicit intervening store/call; that status is a candidate path only, not proof of feasible execution or memory reaching-definition. The generic alias-aware interprocedural audit and `/5` consumer are implemented. Positive consumer validation is recorded by the scan29 `/5` replay: one of four pairs becomes a unique structural candidate after the exact callee is shown to have no aliasing memory effect; three pairs remain possible.

The NFS Shift replay in [PR #2074](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2074)
applies the generic call-result-to-return exporter to 64 frozen scan16–18
P-code snapshots. It records 37 structural paths across 11 functions (28
`CALL`, 9 `CALLIND`) with hashes and byte-for-byte replay. This validates the
generic projection against consumer exports; it does not assign factory
semantics, returned object identity, execution feasibility, or runtime type.

The scan18 load-return replay in [NFS Shift PR #2075](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2075)
freezes three parameter-rooted `LOAD`-to-`RETURN` paths from seven rows in one
function. It validates the structural edge projection only; getter/accessor
semantics and returned object identity remain unassigned.

**Conservative all-path store-dominance audit implemented:** opt-in
`GhidraFunctionPcodeCFG/2` records the explicit entry block and nullable
`LOAD`/`STORE` logical-space and access-width fields; CFG/3 additionally records
physical-space identity and pointer width. The new
`revenginstr-receiver-field-store-load-dominance-audit` requires an exact
program/function pair, a reachable store that dominates the load, matching
space/width, and no possible-effect path between them. Same-space and
unknown-space stores, call-like operations, and unclassified opcodes remain
possible effects. CFG/2 filters stores only by known different logical P-code
space; CFG/3 requires a known different physical space, so unknown physical
identity remains an effect. The output says
`unique_cfg_store_candidate`; it does not compare pointer bases, offsets, or
access-range overlap, model branch feasibility, or assert runtime value flow. The prior
Nevergone evidence demonstrates why this distinction matters: both pairs have
intervening explicit stores, so the current evidence cannot support a positive
reaching-definition result.

**Alias-aware memory access facts and versioned dominance audit implemented:**
the parameter-store exporter can optionally emit one
`GhidraMemoryStoreAccess/1` record for every P-code `STORE`, including
unresolved locations. The opt-in `FieldStoreLoadDominanceAudit/2` joins those
facts to exact CFG operation keys, pins all three input hashes and record
ordinals, and only excludes known different physical spaces or proven
same-parameter-root disjoint byte intervals. Circular ranges are compared
only when exported pointer/address-space geometry agrees; missing, unknown,
or unresolved facts remain possible effects. `/1` remains unchanged when no
sidecar is provided. The first consumer frozen validation is merged in
[Nevergone PR #729](https://github.com/Hanz0Hatt0r1/nevergone-recomp/pull/729):
its exact replay passes for two rows, both `possible_intervening_memory_effect`,
with zero `unique_cfg_store_candidate` rows. The run confirms the contract
fails closed in a real consumer; it does not establish positive memory-value
flow. See the [consumer evidence and replay manifest](https://github.com/Hanz0Hatt0r1/nevergone-recomp/tree/main/docs/evidence/field-store-load-cfg-ccjoystick-init)
and the [field memory alias contract](FIELD_MEMORY_ALIAS_CONTRACT.md).

**Direct-call memory-effect prototype implemented:**
`GhidraDirectCallMemoryEffect/1` is built from exact caller/callee one-function
P-code flow artifacts. `FieldStoreLoadDominanceAudit/3` removes only a
statically resolved direct `CALL` whose non-empty callee body contains only
known write-free P-code operations. The builder does not recurse; nested calls,
indirect calls, unknown operations, and missing flows remain effects. The
prototype is synthetically validated, including a write-free direct-call
case. NFS Shift PRs [#2025](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2025)
and [#2026](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2026)
freeze ten functions and 28 exact parameter-field pairs; no call in those rows
has a complete write-free callee. The expanded consumer replay in [PR
#2027](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2027)
adds two functions and 3 complete write-free direct-call rows. In that NFS
case, one eligible call lies on the exact store-to-load witness, while a
neighboring `unknown_effect` call remains on that path. `/3` therefore keeps the pair
`possible_intervening_memory_effect`; the replay exercises the filter boundary
without promoting a unique candidate or establishing value flow. The follow-up
replay in [PR #2028](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2028)
extends the consumer bundle to thirteen functions and 33 pairs. Two complete
write-free calls occur on two exact witnesses, but each witness also contains
indirect calls, so `/3` keeps both pairs unresolved. [PR
#2029](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2029)
freezes 22 more functions with zero `ParameterStoreField/1` rows and zero
field pairs; its general memory-store sidecar retains 156 STORE facts, 53 with
a parameter root. NFS [PR #2030](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2030)
freezes scan15 over 62 functions with zero indirect calls: it has zero
`ParameterStoreField/1` rows, 238 parameter-load rows and 302 general STORE
facts. NFS [PR #2031](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2031)
freezes scan16 over 70 functions with one indirect call each; 18 parameter
field-store rows produce five exact field pairs across three functions. Its
direct-call sidecar has eight explicit-write sites, three indirect-call
barriers, and one unknown-effect site, with no complete write-free direct
callee. [PR #2032](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2032)
freezes the `/2` comparison: all five pairs have the same status in `/2` and
`/3` (three possible intervening effects and two stores that do not dominate
the load), with zero status changes and zero unique candidates. NFS PR
[#2033](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2033)
freezes scan17 over 49 functions with exactly two indirect calls. It records
17 parameter-field stores, 72 exact pairs across 15 functions, and identical
`/2` and `/3` results (70 non-dominating stores, two possible intervening
effects, no unique candidate). The direct-call sidecar contains 73 explicit
write sites and 30 indirect-call barriers, with no write-free direct callee.
NFS PR [#2034](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2034)
freezes scan18 over 24 functions with exactly three indirect calls: nine
parameter-field stores form five pairs across three roots. `/2` and `/3` agree
on three non-dominating stores and two possible intervening effects, with no
unique candidate. PR [#2035](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2035)
freezes scan19 over two functions with exactly four indirect calls; PR
[#2036](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2036)
freezes scan20 over eight functions with exactly five indirect calls. Both
screens have no parameter-field stores or pairs: scan19 retains 18 parameter
loads and nine general STORE facts, while scan20 retains 79 loads and 42
general STORE facts. NFS PR
[#2037](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2037)
freezes scan21 over three functions with exactly six indirect calls, 28
parameter loads, and 12 general STORE facts, with no parameter-field stores or
pairs. PR [#2038](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2038)
freezes scan22 over one function with exactly nine indirect calls; its two
parameter-field pairs both remain `store_not_dominating_load` in `/2` and `/3`.
It also retains 12 parameter loads and three general STORE facts. PR
[#2039](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2039)
freezes scan23 over the last eligible root with exactly ten indirect calls,
five parameter loads, and four general STORE facts, but no parameter-field
stores or pairs. No dominance audit was run for scans19–21 or 23. The 1,000-row
sample has no further eligible roots under these filters.
The scan10–13
screen records 630 additional exports and 23 ordered pairs without any `/2` to
`/3` status change. These screens remain fail-closed and provide no positive
reaching-definition or runtime value-flow result.
See the [call and memory effect contract](FIELD_MEMORY_ALIAS_CONTRACT.md).

The generic `GhidraDirectCallMemoryEffectClosure/1` builder is merged in
[PR #108](https://github.com/Hanz0Hatt0r1/revenginstr/pull/108). It hash-pins
reachable function flows, bounds total closure work, and terminates direct-call
cycles by function identity. The follow-up
[`FieldStoreLoadDominanceAudit/4`](schemas/field-store-load-dominance-audit-v4.schema.json)
adds an opt-in consumer for closure rows while leaving `/1`–`/3` unchanged.
NFS Shift PRs [#2040](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2040)
and [#2041](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2041)
freeze and replay scan22 through `/4` and `/5`; the two pairs remain
`store_not_dominating_load` in each version.

Remaining propagation work:

1. consumer-validated factory hypotheses linked to call-result-to-return paths; the NFS replay validates structural paths only, so factory semantics and returned object identity remain open;
2. consumer-validated getter/accessor hypotheses from load-to-return evidence; the NFS replay covers three structural paths, but does not label getter/accessor semantics or returned identity;
3. scan29 now validates `/5` with the exact caller root, complete three-operation callee flow/CFG, and hash-pinned memory-access input; it produces one unique structural candidate and leaves three pairs possible. Extend alias-aware reaching definitions only if richer consumer evidence demonstrates a concrete gap, before treating paired field stores and loads as value flow;
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

Receiver projections can additionally join query rows against a hash-pinned
function population. They report query-level resolution and function-level
query/resolution coverage separately, reject duplicate or out-of-population
identities, and omit identities from the summary. The frozen consumer report
remains the evidence for the coverage target. Projection-only benchmark
manifests can summarize already-produced frozen artifacts without rerunning
their expensive acquisition stages. The first consumer report, [Nevergone's
unseen500-v10 receiver coverage](https://github.com/Hanz0Hatt0r1/nevergone-recomp/blob/main/docs/evidence/frozen-unseen500-v10-receiver-coverage/README.md),
finds receiver queries in 100/500 functions (20.0%), a unique-vtable query in
53/500 functions (10.6%), and 66/203 resolved queries (32.5%). This unlabeled
holdout reports coverage only; the >=35% target is not met, and exact-evidence
gates remain unevaluated.

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
Its `/2` contract records the declared feature-group inventory and removals
beside each variant result; that declaration improves report traceability but
does not inspect the consumer's training pipeline. Frozen consumer ablations
and an independent family-held-out evaluation remain open.
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

The generic accept-only router already trains on family-held-out base-classifier
rows and optional sanitized numeric evidence. New inference rows report one
stable policy reason and the number of configured evidence features present
for each scored accept; the reason describes the threshold branch, not a
per-feature attribution.

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

**`FunctionEffectIR/1` and opt-in `/2` projections implemented:** the generic
CLI groups parameter-rooted field reads/writes and P-code direct/indirect call
and return operations by function; `/2` additionally records every P-code
`LOAD` and `STORE` as an exact static memory operation. Each fact retains exact
source-artifact hashes and record ordinals; parameter-rooted field facts remain
`derived_structural`. The memory operation does not resolve pointer targets or
assert write-to-read flow. Both versions are available as pinned benchmark
stages; `/1` remains the default. These versions assign no roles or API
categories. Other effect classes remain open for separately evidenced
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

**Versioned structural summaries implemented:** `revenginstr-structured-summary`
coalesces equivalent `FunctionEffectIR/1` facts into deterministic
`FunctionSummary/1` claims. With `/2` input it emits `FunctionSummary/2` and
groups generic exact memory operations by kind while retaining every support
id and source provenance. Both outputs pin the source Effect IR hash and add
no semantic role or store-to-load claim. Future natural-language rendering may
only restate claims present in these objects.

## M5.4 State-machine recovery

Recover candidate state fields and transition graphs from repeated comparisons/writes, switch structure and cross-function field sharing, with confidence per edge.

**Initial single-function structural candidate detector implemented:**
`revenginstr-state-machine-candidates` requires exact CFG/P-code population
joins, a parameter-rooted field load feeding a comparison and terminal
conditional branch, and a same-parameter/same-offset store reachable from only
one of two CFG successors. It emits hash-pinned `StateMachineCandidateAudit/1`
records by default and `/2` when selecting exact function entries from larger
multi-function captures; `/2` records that scope even when it finds no
candidates. The detector makes no branch-polarity, path-feasibility,
runtime-value, or state
semantics claim. Cross-function field sharing, switch recovery, transition
graphs, confidence per edge, and consumer evaluation remain open.
An exploratory NFS SHIFT replay over fourteen selected functions found two
such structural candidates and twelve non-matches; both positive candidates
were checked against their original P-code, parameter-load, memory-store, and
CFG records (see the
[replay](evidence/state-machine-candidates/nfs-shift-m23-scan/README.md)).

## M5.5 Object-role clustering

Cluster methods using receiver, field, vtable, callgraph and Effect-IR similarity.

**Initial feature contract and clustering kernel implemented:**
`ObjectRoleFeatureSet/1` carries opaque, group-scoped feature hashes and source
provenance; `revenginstr-object-role-clusters` reports per-group Jaccard
similarity, accepted pairs, and their connected components. It emits no role
labels, class identities, inheritance claims, or calibrated confidence.
**Generic feature extraction added:** `revenginstr-object-role-features` uses
Function Effect IR plus optional receiver inference, vtable slots, and callgraph
metrics. It pins all input artifacts and retains source record provenance while
excluding class and function names. Consumer-specific feature adapters and
family-isolated evaluation remain open.

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

**Initial task graph and invalidation plan implemented:**
`AnalysisTaskGraph/1` pins task configuration hashes, artifact inputs/outputs,
and explicit dependencies. `revenginstr-analysis-invalidation-plan` validates
producer joins and acyclicity, returns deterministic topological order, and
reports downstream invalidations with direct or dependency causes. It only
plans; it does not execute analyzers or select evidence requests.
`revenginstr-analysis-task-cache-keys` computes a content-addressed key per
task from source artifact hashes, task configuration, implementation hash,
and dependency keys. `revenginstr-analysis-task-cache-lookup` verifies a
caller-managed manifest and content-addressed output bytes without restoring or
executing them. `revenginstr-analysis-task-cache-restore` restores verified
bytes only to caller-pinned relative paths, refuses symlinked paths and
different existing files, and never executes cached tasks. Cost-aware
scheduling and end-to-end consumer convergence remain open.

### M6.2 Evidence request planner

**Initial bounded planner implemented:**
`EvidenceRequestCandidates/1` accepts only caller-approved action types with
finite per-action limits, and `revenginstr-evidence-request-plan` ranks them by
caller-supplied downstream leverage and uncertainty reduction per cost under
a fixed budget. It emits a plan only; the consumer still provides, reviews,
and executes any evidence action. Calibration of the supplied value/cost
estimates and end-to-end consumer convergence remain open.

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

**Terminal states standardized (2026-10-17):** `AnalysisDecisionLedgerEvent/1`
uses the six bounded terminal states below; unsupported states fail validation.

- `accepted_exact`;
- `accepted_high_confidence`;
- `review_required`;
- `escalated_conflict`;
- `unsupported`;
- `budget_exhausted`.

### M6.4 Decision ledger

**Initial ledger and audit implemented:** `revenginstr-decision-ledger-audit`
checks unique event IDs, contiguous per-subject indexes and prior-state
continuity plus stable subject artifact provenance. Events retain evidence
additions, responsible actor, reason codes, confidence delta and provenance;
the hash-pinned audit emits aggregate counts without subject or analysis
identities. Transition policy remains consumer-owned.

### M6.5 Human feedback

**Initial feedback contract implemented:** [`AnalysisFeedback/1`](../schemas/analysis-feedback-v1.schema.json)
supports confirmed, rejected, partially-correct, ambiguous, and
needs-more-evidence outcomes. Consumer-owned rows pin their target and cited
evidence, retain opaque reviewer metadata and reviewer-assessed provenance
quality, and require `training_eligible: false`; separate label adjudication
remains necessary before training use.

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

# 13. M8 — Whole-program type and layout recovery

## Goal

Move from receiver/vtable hypotheses to an auditable whole-program type model: function prototypes, object layouts, field types, inheritance/composition and lifetime relationships, without converting weak inference into exact truth.

## Work

### M8.1 Function prototype recovery

Infer evidence-backed candidates for:

- parameter count and calling-convention compatibility;
- pointer/reference/scalar distinctions;
- return-value shape and candidate type;
- `this`/receiver identity where ABI and provenance support it;
- compatible prototypes across direct/indirect call sites;
- confidence and conflict reasons for every proposed signature.

Exact debug/import/type information always outranks inferred prototypes. Conflicting call sites fail toward review rather than being silently unified.

`FunctionPrototypeHypothesis/1`, `FunctionPrototypeGold/1`, and a scoped
compatibility evaluator exist with synthetic exact fixtures. The first
conservative inference path now emits hash-linked review hypotheses, but
independent consumer gold and full program coverage accounting are still
absent, so M8.1 remains partial.
`GhidraFunctionPrototype/1` now supplies a structured, hash-pinned snapshot of
the signatures already stored in Ghidra, including declaration source and ABI.
`DirectCallArgumentObservation/1` now records observed argument counts and
varnode widths at resolved direct P-code call sites with exact source links.
The call observations do not claim that all callers were exported or recover
pointer/scalar types. `FunctionPrototypeCallsiteCompatibility/1` compares
observed direct-call arity with stored fixed or variadic signatures, but its
per-call results do not establish whole-program compatibility.

`GhidraDecompilerParameters/1` now records High-P-code formal parameter
symbols, type widths/kinds, storage, `this`/hidden-return markers and return
shape with per-function decompilation status. `revenginstr-prototype-infer`
joins these rows to hash-pinned direct-call argument observations and emits
`FunctionPrototypeHypothesis/1` review records. It treats call arity as a
constraint, never as a type label; conflicting call sites are marked
`conflicted`, and emitted confidence scores stay below the evaluator's
high-confidence threshold. A real Ghidra replay covers the two-function sample
fixture. The generic inference path exists, but independent consumer gold, full
program coverage accounting, calibrated confidence and indirect-call
constraints remain required before M8.1 is complete.

### M8.2 Struct/class layout recovery

Build a versioned `TypeLayoutHypothesis`-class representation containing:

- minimum observed object size;
- field offsets, widths and candidate scalar/pointer/object/container types;
- vtable anchors and candidate base relationships;
- constructor/destructor and neighboring-method support;
- array/stride and repeated-element candidates;
- composition versus inheritance uncertainty;
- source evidence and confidence per field/relation.

Field overlap, incompatible widths, conflicting base-object hypotheses and architecture-specific padding remain explicit conflicts.

### M8.3 Allocation, ownership and lifetime

Correlate allocation size, constructor/vtable stores, destructor/free/refcount-like effects and escape behavior into bounded lifetime hypotheses. Distinguish observed allocation/free facts from inferred ownership (`owned`, `borrowed`, `shared`, `unknown`).

### M8.4 Enums, bitfields and containers

Recover candidates from repeated comparisons, masks, shifts, strides, size/capacity patterns and iterator-like access. Generic container-shape recognition must remain compiler/ABI-aware and must not encode game-specific STL or engine semantics as truth.

### M8.5 Evaluation

Create synthetic exact-layout fixtures plus consumer-owned frozen objects with independently verified fields and prototypes. Report field-offset precision/recall, compatible-type accuracy, layout conflict rate, prototype compatibility and high-confidence reviewer acceptance.

**Hypothesis contract and conservative builder implemented:**
`TypeLayoutHypothesis/1` stores program-pinned candidate size bounds, field
access/type observations, vtable anchors, candidate relationships, and
evidence-backed conflicts. `revenginstr-type-layout-hypothesis` joins exact
STORE rows and optional parameter-rooted LOAD TSV rows only through
reviewer-supplied `TypeLayoutMemberMap/1` keys and retains both source hashes.
Optional `TypeLayoutSizeReview/1` input adds exact size only with independently
hash-pinned source evidence; disagreements with the observed extent or other
size reviews become explicit conflicts. Its NFS SHIFT replay reproduces
reviewed offsets and a 56-byte lower bound, with a four-byte `data_pointer`
candidate at `+0x20` and the observed `0x00af0860` vtable anchor; the pointer's
referent and exact object size remain unresolved. The Nevergone
`CCJoyStick::init` projection has a 337-byte observed lower bound; symbolized
factory code requests a 340-byte allocation and calls the exact constructor.
Nine of its thirteen observed fields now have reviewer-pinned type candidates:
three `cocos2d::CCSprite*` fields, two integers, and four booleans. The other
four fields, containing-object vtable, ownership, and audit-acceptance metrics
remain open. Both consumers exercise layout recovery, while broader
independent field/type gold validation remains open. Synthetic fixtures
validate the wire contract and fail-closed conflicts. `TypeLayoutGold/1` and
`revenginstr-type-layout-evaluate` now score field offsets only inside explicit
audited coverage, and report compatible reviewed-type accuracy, coverage,
conflict rates, and review acceptance. Synthetic tests exercise partial-gold
handling. Independent consumer layout/prototype gold sets and a field-level
confidence signal are still absent. The synthetic prototype evaluator can now
be hash-linked to the layout report, but no consumer prototype gold has been
adjudicated, and high-confidence field acceptance remains not evaluated. M8.5
is therefore partial, not complete.

## Exit criteria

- a stable versioned whole-program type/layout hypothesis schema;
- >=90% audit acceptance for high-confidence recovered fields/signatures on frozen consumers;
- zero overwrite of contradictory exact type/vtable evidence;
- every inferred field, signature and relationship retains provenance and a reason/conflict code;
- at least two consumers exercise layout recovery on independently verified objects.

Stretch: >=95% high-confidence acceptance and useful recovered layouts for >=60% of high-value object-method clusters.

---

# 14. M9 — Hybrid static/dynamic analysis

## Goal

Use bounded runtime and interventional evidence to resolve ambiguities that static analysis cannot safely close, while keeping execution consumer-controlled and fully provenance-linked.

## Work

### M9.1 Probe request contract

Extend the M6 evidence planner with versioned requests for caller-approved bounded actions such as:

- function-entry/exit observation;
- field watch/read/write capture;
- argument/return sampling;
- bounded call/dispatch tracing;
- allocation/lifetime observation;
- before/after state snapshots;
- consumer-defined differential or interventional runs.

`revenginstr` plans and validates requests; consumers decide whether and how executable probes are implemented and run. The core must never synthesize arbitrary executable instrumentation and run it without an explicit consumer boundary.

### M9.2 Static/runtime correlation

Join runtime events to static function, instruction, object, field and callgraph identities using exact program/build hashes and normalized addresses. ASLR/load-bias mapping, sampling gaps and unmatched events are explicit metadata rather than guessed joins.

### M9.3 Differential and interventional analysis

Compare bounded runs where one caller-controlled input/state/action differs. Rank candidate causal relationships by reproducible observation while retaining `correlation`, `intervention_support` and `confirmed_exact` as distinct evidence classes.

### M9.4 Runtime value-flow confirmation

Use runtime observations to confirm or reject high-value static candidates such as receiver identity, field write/read linkage, state transitions, factory returns and lifetime events. A runtime witness can strengthen a candidate but cannot retroactively make unsupported static paths exact.

### M9.5 Information-gain evaluation

Measure requested-probe cost, completion rate, decisive-result rate, uncertainty reduction, downstream decisions unlocked and disagreement with static predictions.

## Exit criteria

- stable probe-request and runtime-correlation schemas;
- deterministic replay of captured runtime evidence into the decision ledger;
- >=50% of completed planner-selected probes on a frozen unresolved set produce a decisive accept/reject or materially narrower hypothesis;
- runtime/static identity mismatches fail closed;
- no automatic executable probe bypasses consumer approval or configured resource bounds.

Stretch: >=70% decisive probe rate and >=30% reduction in unresolved high-value tasks after bounded hybrid analysis.

---

# 15. M10 — Semantic Program Graph

## Goal

Unify function effects, recovered types, object roles, state machines, resources and execution relationships into a queryable evidence-linked graph of the analyzed program.

## Work

### M10.1 Graph schema

Define stable node families such as:

- function/method;
- type/object instance class;
- field/global;
- vtable/dispatch slot;
- state/state machine;
- resource/asset identifier;
- subsystem/role cluster;
- callback/event;
- thread/execution context;
- external API/category.

Define versioned edge families such as `calls`, `dispatches`, `reads`, `writes`, `owns`, `contains`, `creates`, `destroys`, `transitions`, `registers_callback`, `invokes_callback`, `loads_resource`, `runs_on_context` and `candidate_base_of`.

### M10.2 Provenance and confidence

Every graph node/edge retains evidence class, support ids, confidence/calibration where applicable, conflict state and derivation lineage. Equivalent facts may be coalesced only when their upstream evidence is preserved.

### M10.3 Conflict-aware graph construction

Represent competing hypotheses rather than forcing a single world model. Graph queries must be able to select exact-only, accepted-high-confidence or exploratory views.

### M10.4 Program-level queries

Support reproducible queries such as:

- what writes this state field before this dispatch;
- which methods share this recovered object layout;
- which callbacks can reach this subsystem;
- which resources are referenced by this role cluster;
- which unresolved indirect calls block a path from input to state transition;
- which conclusions depend on one weak upstream hypothesis.

### M10.5 Evaluation

Build consumer-owned gold subgraphs for independently understood subsystems and report accepted-edge precision, relation-specific recall where labels are complete, unsupported-edge rate and provenance completeness.

## Exit criteria

- stable semantic graph schema and deterministic builder;
- >=0.95 precision for accepted graph edges on frozen audited subgraphs;
- 100% provenance coverage for accepted inferred/learned edges;
- graph conflicts remain visible and cannot silently collapse into accepted facts;
- at least two consumer subsystems can be reconstructed and queried end to end.

Stretch: accepted-edge precision >=0.98 with useful cross-function/state/object graph coverage across multiple projects.

### Current implementation status (2026-10-19)

`SemanticProgramGraph/1` projects `FunctionEffectIR/1` and `/2` into
deterministic program, function, operation, and parameter-rooted field
entities. Resolved direct calls and structural field reads/writes retain
source effect ids and artifact hashes; unresolved and indirect calls stay
explicit, and multiple direct targets at one call site remain contested.
Cross-export opcode disagreements at the same function, address, and P-code
time also remain contested.

`SemanticProgramGraph/2` optionally joins
`GhidraIndirectReceiverType/1` observations by exact function entry, call
address, and P-code time. It retains absent receivers and unmatched rows,
records raw type metadata as observations, and emits no inferred dispatch
target. A captured Ghidra replay for GT5 Prologue function `00032830` validates
one `CALLIND` join from exported data; see
[`SemanticProgramGraph/2 replay`](evidence/semantic-program-graph-v2/gt5-prologue-00032830/README.md).

The graph families are still structural slices of M10.1–M10.3. Dispatch
recovery, recovered layouts, roles, states, resources, callbacks, execution
contexts, broadly scoped semantic gold graphs, and M10 exit criteria remain
open.

`revenginstr-semantic-program-query` now selects nodes and edges by kind,
relation, indirect-call state, conflict state, function entry, operation
address, field offset, and provenance id. It emits a hash-pinned
`SemanticProgramQueryResult/1` with endpoint context and supports exact-only,
accepted-high-confidence, and exploratory views. A replay over the captured
Ghidra graph returns its `CALLIND` and exact receiver observation; the same
query runner also returns endpoint context and preserves source support. This
is the first generic selector layer for M10.4. Queries that require CFG
feasibility, field meaning, layout equivalence, resource/state/callback paths,
broadly scoped semantic subsystem gold data, and all M10 exit criteria remain
open. A separate bounded path query now enumerates simple routes over exact direct-call edges,
retaining caller/callee function context and call-operation,
membership-edge, and call-edge provenance. It also surfaces unresolved,
indirect, and conflicted call sites in the source's direct-call reachable
region as candidate frontiers with a witness path and membership provenance;
it does not assign those sites a target, claim that they block the target
path, or establish CFG-feasible execution. The NFS SHIFT replay in
[`SemanticProgramPathQuery/1 replay`](evidence/semantic-program-path-query/nfs-shift-call-path/README.md)
returns the captured route `00a45520 → 00a40550 → 00886930`.

The path query also accepts a hash-pinned Ghidra Function P-code CFG artifact
and joins call sites by exact function entry, address, P-code time, and opcode.
It records the call block and a successor-path witness from the function entry.
The NFS SHIFT CFG/3 replay confirms the call at `00a4556d` is in entry-reachable
block 3; block-graph reachability does not establish branch-predicate
feasibility or runtime execution.

`SemanticProgramGraphGold/1` and
`SemanticProgramGraphEvaluation/1` now define scoped consumer gold and report
relation-specific recall only where labels declare completeness. The evaluator
also reports unsupported candidate-edge rate and provenance-field coverage.
The evaluator and gold schema reject relation/node-kind mismatches; the
evaluator also checks source opcodes when those operations are present, so
malformed labels cannot silently lower recall.
Reviewer-curated raw P-code projection audits match 2/2 GT5 and 7/7 NFS SHIFT
direct-call edges; the Nevergone consumer-owned player-facing subgraph matches
all 3 documented calls (see the
[replay](evidence/semantic-program-graph-evaluation/nevergone-player-horizontal-facing/README.md)).
The NFS M2.3 consumer-owned slice matches 7 calls, 2 reads, and 1 write (see
its [replay](evidence/semantic-program-graph-evaluation/nfs-m23-00a45520/README.md)).
All twenty-two edges have complete provenance fields. Both consumer golds are
narrow structural interpretations, without independent runtime
corroboration; the NFS gold does not assign field meaning or prove memory
flow. Calibrated accepted edges and reconstruction/query of two broader
semantic subsystems remain open, so M10.5 and its exit criteria are not
complete.

---

# 16. M11 — Active learning and reviewer-feedback loop

## Goal

Turn reviewed analysis outcomes into safer future models without leaking evaluation sets, amplifying model mistakes or silently treating feedback as ground truth.

## Work

### M11.1 Feedback quarantine

`AnalysisFeedback/1` remains non-training by default. Candidate examples enter a versioned quarantine dataset that retains reviewer, target, evidence, model/version, family and source-dataset provenance.

### M11.2 Adjudication and disagreement

Require explicit promotion from feedback to label. Support multiple reviewers, conflicting outcomes, stale-evidence invalidation and `ambiguous`/`unknown` labels. Measure reviewer agreement and preserve disagreement instead of majority-voting it away by default.

### M11.3 Leakage and family gates

Before promotion into training:

- detect duplicate/near-duplicate identities and structural families;
- reject overlap with current frozen evaluation sets;
- record dataset lineage and split consequences;
- prevent model-generated pseudo-labels from being promoted as human truth;
- require a new untouched holdout when a prior holdout materially influenced a rule or threshold.

### M11.4 Retraining and promotion

Automate candidate training runs, family-isolated evaluation, calibration, router gates, cross-project drift checks and before/after benchmark deltas. Promotion requires configured non-regression gates; failed candidates remain retained experiments, not deployed models.

### M11.5 Rollback and lineage

Every promoted model records exact training data, feature/schema versions and parent model. Keep one-command rollback to the prior accepted model/config and preserve decisions made under older versions.

## Exit criteria

- no reviewer feedback becomes training data without explicit adjudication and leakage checks;
- every promoted model has reproducible data/model lineage and frozen benchmark deltas;
- automated promotion cannot lower hard router precision or exact-evidence safety gates;
- rollback is deterministic;
- active-learning sampling demonstrably reduces review effort or improves a target metric on a later untouched holdout.

---

# 17. M12 — Architecture and ABI expansion

## Goal

Make architecture-specific decoding and ABI knowledge adapters around a normalized evidence core rather than assumptions embedded in semantic/ML logic.

## Work

### M12.1 Normalization boundary

Document which facts are architecture-specific (instruction decoding, register classes, pointer width/tagging, calling convention, vtable ABI, relocation/veneer patterns) and which normalized facts are portable above the adapter boundary.

No classifier, router, Effect IR, semantic graph or orchestration rule may require a raw architecture identity unless an experiment explicitly declares itself architecture-specific.

### M12.2 Expansion order

Target, in practical priority order:

1. retain ARM32 and x86-32 regression coverage;
2. ARM64/AArch64;
3. x86-64;
4. PowerPC/PPU and PPC64-class ABIs needed by supported consumers;
5. MIPS/other architectures only when a real consumer justifies the adapter.

PowerPC support should explicitly cover the calling-convention, function-descriptor/TOC and branch/veneer behaviors required by the selected ABI rather than treating `PowerPC` as one generic mode.

### M12.3 ABI/vtable adapters

Generalize vtable/object dispatch contracts beyond ARM32 Itanium where evidence supports it. Keep ABI-specific slot/header rules isolated and expose the same normalized receiver/dispatch facts upward.

### M12.4 Cross-architecture fixtures

Create legal synthetic fixtures for calling conventions, direct/indirect calls, tagged/thunked targets, vtables, field access, return values and representative compiler idioms on each supported ISA/ABI combination.

The native P-code C lowerer also has an ARM64 execution gate for its x86
binary80 path. It checks a small generated-code fixture, including minimum
binary80 subnormal arithmetic. This does not establish full-corpus/runtime
parity or exact equivalence for rare double-rounding cases on hosts with wider
`long double` precision; the guest floating-point control state still needs an
explicit consumer mapping.

### M12.5 Transfer evaluation

Run architecture-held-out and project-held-out checks to distinguish semantic transfer from architecture fingerprinting. Report feature drift and acceptance calibration separately for each ISA/ABI.

## Exit criteria

- at least four validated ISA/ABI combinations including existing 32-bit consumers;
- ARM64, x86-64 and one PowerPC-class consumer/fixture path reach the normalized evidence layer without title-specific semantic code;
- shared schemas remain architecture-neutral or use explicit versioned adapter metadata;
- exact exporter/receiver fixtures remain regression-free per architecture;
- cross-architecture ML evaluation shows no hidden raw-ISA identity dependency in portable models.

---

# 18. M13 — Decompiler and recompiler integration

## Goal

Project accepted analysis back into the tools where reverse-engineering and recompilation work happens, while keeping every mutation reversible, confidence-aware and auditable.

## Work

### M13.1 Analysis apply bundle

Define a versioned bundle containing only explicitly selected accepted suggestions such as:

- function/method names;
- function signatures and calling conventions;
- recovered structs/classes/field names and types;
- class/vtable relationships;
- comments and semantic summaries;
- bookmarks/tags for review/escalation;
- state/role/resource annotations;
- stable references back to decision-ledger evidence.

### M13.2 Safe mutation policy

Never overwrite stronger user/exact-debug information with weaker inference. Default to suggestion namespaces/comments/bookmarks for learned or inferred facts. Require explicit policy for renames or datatype application and retain a complete undo manifest.

### M13.3 Ghidra integration

Provide a read/validate/apply path for a copy or caller-approved Ghidra project. Before applying, verify program hash/build identity, schema compatibility and target-address/function identity. Emit an application report with applied, skipped, conflicted and stale suggestions.

### M13.4 Consumer/recompiler integration

Expose stable machine-readable outputs that can seed symbol maps, type headers, stub declarations, TODO/review queues and provenance comments in recompilation/decompilation repositories without embedding consumer-specific source layout in the core.

### M13.5 Round-trip audit

Re-export affected metadata after apply and verify that accepted changes round-trip to the intended identities. Never treat successful application as new independent evidence.

## Exit criteria

- versioned reversible apply-bundle contract;
- zero silent overwrite of stronger existing user/exact information in integration fixtures;
- deterministic dry-run and apply reports;
- at least one Ghidra consumer and one recompilation/decompilation consumer use the bundle end to end;
- every applied inferred/learned suggestion remains traceable to the originating decision ledger and evidence.

---

# 19. Evaluation and CI matrix

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
| Type/layout gold fixtures | signatures, fields, lifetime relationships | M8+ |
| Bounded hybrid replay | static/runtime correlation and probe value | M9+ |
| Semantic graph audit | accepted relation precision/provenance | M10+ |
| Feedback promotion audit | leakage/adjudication/model lineage | M11+ |
| Cross-architecture parity | normalized evidence portability | M12+ |
| Apply-back round trip | safe reversible decompiler integration | M13+ |
| Cross-project holdout | transfer | M7+/release |
| Determinism test | reproducibility | releases |
| Performance benchmark | scalability | exporter/orchestrator changes |

A behavior-changing PR should include before/after metrics or a pointer to the retained full benchmark artifact when the heavy benchmark is not suitable for PR CI.

---

# 20. Data and label strategy

1. Keep source names, addresses, raw strings and title-local IDs in audit/trace artifacts unless a declared experiment intentionally studies them.
2. Preserve evidence quality tiers with machine-readable reason codes.
3. Do not manufacture negatives: unknown is not automatically `other`, `engine` or non-game.
4. Prioritize manual evidence work on high-disagreement, high-centrality and repeated-family cases.
5. Once a frozen set materially influences a new rule/threshold, retire it as the final untouched test and create a new sealed holdout.
6. Keep reviewer feedback quarantined until explicit adjudication, family/duplicate checks and frozen-set leakage checks complete.
7. Preserve model-generated hypotheses as hypotheses; pseudo-labels never become human ground truth by provenance erasure.
8. Version recovered type/layout and semantic-graph gold data separately from model predictions so later corrections remain auditable.
9. Cross-architecture evaluation must separate architecture transfer from project/domain transfer.

---

# 21. PR-sized implementation sequence

## P0 — immediate

1. ✅ Canonical benchmark manifest schema.
2. ✅ One-command benchmark runner.
3. ✅ Standardized combined metric projections for classifier, receiver, router and validation reports.
4. ✅ Exporter/schema inventory; refreshed current three-repository snapshots and added source-list coverage.
5. ✅ Receiver residual taxonomy v1.
6. ✅ Frozen receiver coverage report; first consumer report records current coverage below the M2.6 target.
7. ✅ Classifier threshold/calibration sweep tooling.
8. ✅ Classifier error-cluster report.
9. ✅ Router evidence-aware reason codes and scoring inputs; inference records the threshold branch and present evidence-feature count.
10. 🟡 Frozen router >=0.970 precision / >=0.55 coverage gate: generic evaluator and hash-bound holdout checks implemented; independent labeled consumer evidence is still required to pass the gate.
11. ✅ Hash-pinned Markdown + JSON KPI dashboard generator and schemas; first hash-pinned consumer artifact is published in the [Nevergone dashboard evidence](https://github.com/Hanz0Hatt0r1/nevergone-recomp/tree/main/docs/evidence/nevergone-kpi-dashboard-v1) with JSON output and replay manifest.

## P1 — after measurement is stable

12. ✅ Receiver provenance graph schema, reference validation, and initial exact one-hop projections; the unified program-level graph remains open under M10.
13. 🟡 Interprocedural receiver propagation v1; bounded caller-argument, field-store/load, and return anchors plus exact one-hop joins are implemented, while positive memory-flow and semantic receiver validation remain open.
14. ✅ Initial Effect IR schema + structural extractor v1; additional effect classes and semantic evaluation remain open.
15. ✅ Initial generic semantic-label/evaluation format and paired scorer; family-isolated consumer gold sets remain open.
16. ✅ Structured function summary v1; [`FunctionSummary/1–2`](FUNCTION_SUMMARY.md) preserves claim provenance and pins the source Effect IR hash.
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


## P3 — whole-program recovery and active evidence

28. 🟡 Function prototype hypothesis/gold schemas, coverage-aware compatibility evaluator, and synthetic fixture implemented; inference and independent consumer gold remain open.
29. 🟡 Object/type layout hypothesis schema, exact-size and field-type review inputs, synthetic fixtures, deterministic reviewer-keyed read/write builder, and NFS SHIFT plus Nevergone projections implemented; broader field/type gold validation remains open.
30. Allocation/lifetime/ownership evidence projection.
31. Bounded runtime probe-request and correlation contracts.
32. Static/runtime differential replay and information-gain metrics.
33. Semantic Program Graph schema and deterministic builder.
34. 🟡 Scoped graph-gold schema/evaluator, two raw P-code projection audits, and narrow Nevergone/NFS consumer-owned structural golds implemented; accepted-edge precision and end-to-end semantic subsystem gates remain open.
35. Feedback quarantine, adjudication and leakage-gated training promotion.

## P4 — architecture and integration

36. Architecture/ABI normalization contract and adapter test matrix.
37. ARM64/AArch64 exporter/ABI parity path.
38. x86-64 exporter/ABI parity path.
39. PowerPC/PPU-class adapter prototype and fixtures.
40. Cross-architecture portable-model audit.
41. Versioned decompiler apply bundle and dry-run validator.
42. Safe Ghidra apply/undo path.
43. Recompiler/decompilation consumer integration and round-trip audit.

---

# 22. Recommended execution order

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


### Wave G — whole-program reconstruction

M8: signatures, object layouts, field types, ownership/lifetime and independently audited type hypotheses.

### Wave H — active evidence and program model

M9 + M10: bounded static/dynamic evidence acquisition followed by a provenance-linked Semantic Program Graph. Dynamic evidence remains consumer-controlled and graph conflicts remain explicit.

### Wave I — learning loop

M11: reviewer-feedback quarantine, adjudication, leakage-safe retraining and promotion/rollback gates. No feedback enters training merely because a reviewer touched it.

### Wave J — architecture and workflow integration

M12 + M13: validate the normalized core across ARM64, x86-64 and PowerPC-class targets, then project accepted results back into decompiler/recompiler workflows through reversible apply bundles.

At the end of Wave J, `revenginstr` should qualify as a multi-architecture autonomous reverse-engineering analysis platform rather than only an assisted-analysis toolkit.

---

# 23. Definition of done

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
10. downstream consumers can distinguish exact, inferred and learned evidence;
11. architecture-specific behavior is isolated below a documented normalization boundary when the feature is intended to transfer;
12. any active/runtime action is bounded, caller-approved and replayable from captured evidence;
13. any apply-back mutation is dry-runnable, conflict-aware, reversible and provenance-linked.

---

# 24. Major risks

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


### Type/layout inference amplifies one wrong object hypothesis

Mitigation: per-field provenance, conflict-preserving layouts, exact-evidence precedence, compatibility checks at call sites and no silent propagation through unresolved aliases.

### Runtime probes become unsafe or unbounded

Mitigation: the core only plans allowlisted bounded evidence requests; consumers explicitly approve and implement executable probes, with build identity, budget and replay metadata pinned.

### Feedback loop trains on its own mistakes

Mitigation: quarantine feedback, require adjudication, preserve model-versus-human provenance, enforce family/frozen-set leakage checks and gate every promotion against untouched evaluation.

### Architecture fingerprints leak into portable models

Mitigation: explicit normalization boundary, cross-architecture holdouts, feature audits and architecture-specific experiments clearly marked non-portable.

### Apply-back corrupts analyst-owned decompiler state

Mitigation: dry-run by default, stronger-existing-evidence precedence, suggestion namespaces for weak facts, explicit conflict reports and reversible undo manifests.

---

# 25. Success states

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


## Whole-program reconstruction milestone

- high-confidence recovered signatures/layouts reach >=90% audit acceptance;
- accepted semantic-graph edges reach >=0.95 precision on frozen audited subgraphs;
- bounded hybrid probes materially reduce unresolved high-value cases;
- object/state/type relationships remain queryable with complete provenance;
- reviewed corrections can enter training only through adjudicated leakage-safe promotion.

## Multi-architecture integration milestone

- normalized evidence is validated on at least four ISA/ABI combinations, including ARM64, x86-64 and a PowerPC-class path;
- portable models do not require raw architecture identity;
- accepted analysis can be dry-run/applied/undone in a decompiler workflow;
- at least one recompilation/decompilation consumer uses generated signatures/types/annotations with decision-ledger provenance;
- a new supported binary can progress from evidence extraction to a queryable program model while escalating genuinely ambiguous cases instead of inventing certainty.

---

# 26. Immediate next action

**M2.3 capture/replay now covers the planned scan22 recapture and an exact-root
follow-up.** Nevergone's frozen CFG/3 and memory-store sidecar replay is pinned
in [PR #729](https://github.com/Hanz0Hatt0r1/nevergone-recomp/pull/729). NFS
Shift [PR #2073](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2073)
adds read-only scan22 recapture and scan24 exact-root artifacts with hash-pinned
replay. Scan22 captured four callee CFG/3 records, twelve callee memory-access
facts and five exact roots across callers, but none for its selected caller.
Its `/5` replay preserves indirect-call and unknown-effect barriers and leaves
both pairs unresolved. Scan24 has two exact roots and seventeen memory facts;
its single pair remains a possible intervening memory effect. Scan23 exhausted
the original 1,000-function sample under its existing filters. These results
validate bounded evidence handling and fail-closed behavior; they do not
validate runtime value flow or a positive alias-filtering promotion.

A fresh x86-32 sample screened 100 additional Ghidra functions outside that
slice. It produced 12 parameter-field stores and 133 parameter loads, but no
exact formal/offset pair. A separate exact-root replay did find a direct call
whose callee flow has no stores or nested calls; `/5` classified that call as
`no_aliasing_memory_effect`. Its caller pair still remains
`store_not_dominating_load` in `/2` and `/5`, because a CFG path reaches the
load without executing the store. This validates the exact-root call-effect
path, but does not promote the pair or validate runtime value flow.

Four follow-up address-stratified screens (`next100b`–`next100e`) covered 400
planned functions and exported 31 parameter-field stores and 459 parameter
loads. They produced 14 exact same-formal/offset pairs. Manual replay of the
dominating candidates found two pairs in one function in `next100b`, two in
`next100d`, and one in `next100e`; `/2` kept each at
`possible_intervening_memory_effect`. The remaining pairs checked in those
screens had stores that did not dominate their loads. The `next100e` strongest
candidate was replayed through `/5` as well: its direct-call closure returned
`unknown_effect` because exact caller-formal argument roots were absent and
the closure contained unresolved/indirect operations and missing CFG facts, so
`/5` preserved `possible_intervening_memory_effect`. The argument subtree
showed a global address and a loop value rather than the caller's formal
parameter; treating that as a non-alias proof would be unsound. These screens
add no positive alias-filtering promotion and do not establish memory value
flow.

A separate high-priority prefilter selected 169 previously unseen functions
whose mined instruction-level sequence was `STORE`, direct `CALL`, `LOAD`.
Fresh High-P-code exports produced zero P-code `STORE` operations, zero
parameter-field stores, and zero parameter-field loads across those functions;
all 169 general memory-store sidecars were empty. A fresh flow export for one
sample contained two `CALL` rows and one `RETURN`, confirming that the corpus
labels are instruction-level candidate features and must not be read as
Ghidra P-code memory facts. Keep that corpus as an address-generation aid only;
future candidate prioritization must confirm actual High-P-code memory
operations before exporting call closures.

A higher-complexity 100-function screen (`next100f`) exported 14
parameter-field stores and 1,154 parameter loads, forming nine exact pairs.
Six pairs in two functions had a store-bypass path. Three pairs in a third
function had dominating stores but remained `possible_intervening_memory_effect`
in `/2`. A fresh `/5` replay of one of those pairs kept that status: all eight
calls in the effect bundle were `unknown_effect`, with missing direct-call
roots and a transitive closure containing stores and indirect calls. This
rechecked the candidate and did not produce an alias-filtering promotion.

A subsequent screen (`next100g`) constrained the corpus prefilter to one direct
call and exported 25 parameter-field stores and 507 parameter loads across 100
functions, producing two exact pairs in one function. Fresh `/2` and `/5`
replays agreed: the first pair was `unique_cfg_store_candidate` because its
store dominates the load and no possible memory effect lies on the witness;
the second stayed `possible_intervening_memory_effect`. The intervening call
for the second load was `unknown_effect`; its only exact argument root mapped
callee parameter 2 to caller parameter 3, while the other arguments came from
loads. Distinct caller formals still may alias. This validates both a positive
structural candidate path and an unknown-effect barrier, without a `/2` to
`/5` status change or a runtime value-flow claim.

A follow-up one-call screen (`next100h`) exported 20 parameter-field stores
and 408 parameter loads across 100 functions, forming nine exact pairs. The
fresh `/2` and `/5` replays agreed on all nine: two
`unique_cfg_store_candidate`, five `possible_intervening_memory_effect`, and
two `store_not_dominating_load`. A subsequent live replay found that two of
the three apparent exact call-site roots were false: their argument roots were
loop-carried `MULTIEQUAL` values, but the exporter had treated shared
`HighVariable` identity as proof of a direct formal root and ignored changing
backedge offsets (`+0x12c` and `+0x13a * 4`). The exporter now rejects derived
values as direct roots and accepts a `MULTIEQUAL` only when every incoming
branch resolves to the same formal and byte offset. Replaying the same calls
removed both false roots; the third root, a direct constant-offset path from
caller parameter 0 at `+0x98`, remains exact. Rebuilding the interprocedural
effects and `/5` audit from the corrected root sidecar retained seven
`unknown_effect` and two `missing_callee_flow` rows, with all nine audit
statuses unchanged; no alias-filtering promotion was justified. This corrects
the earlier root evidence and makes loop-carried argument mapping fail closed.

A fresh top-ranked 20-function screen (`next20i`) used previously unseen
mining candidates indicating one direct-call feature and high instruction-level
`STORE` and `LOAD` counts. The Ghidra exports contained zero parameter-field
stores, 434 parameter-field loads, and 535 general memory-store facts; 320 of
those stores had parameter-rooted constant offsets, but none stored a value
rooted at a formal parameter, so the screen produced no compatible
field-store/load pair.
This rejects instruction-count ranking for pair discovery and reinforces that
follow-up batches should start from exported parameter-field stores and loads.

A refined 53-function `__thiscall` sample with 300–600-byte functions and
instruction-level direct-call features produced 29 parameter-field stores and
390 parameter loads, forming 30 exact same-formal/offset pairs. CFG/3 replays
of all seven pair-bearing functions classified all 30 as
`store_not_dominating_load`; none qualified for interprocedural call-effect
filtering. The calling-convention and size signals improved store yield over
`next20i`, but the sampled functions still did not produce a dominating
store/load pair.

A writable Parameter ID replay exposed a data-preparation gap in the earlier
`next100d` closure investigation. On a clean copy of the SHIFT Ghidra project,
`ApplyDecompilerParameterId` recovered signatures for `00806ef0`, `008868c0`,
`006382b0`, and `00638020`; subsequent read-only P-code exports then showed
1, 2, and 3 actual arguments at their direct-call edges. The prior sidecar
mapping `00638020.param0` to `006382b0.param1` did not survive this replay:
the actual argument is a `MULTIEQUAL` of two `0062e1a0` call results, and the
fresh caller-root sidecar has no row. The intermediate
`008868c0.param0` → `006382b0.param0` mapping remains exact; the outer
`00806ef0` argument is an `INT_OR` value derived from `Stack[0x4]`, so it also
has no exact formal-root row. A fresh `/5` replay paired the one parameter
field store with two loads. Both audit rows remain
`possible_intervening_memory_effect`; the call at `00806f1a` to `008868c0`
returns `unknown_effect` for both pairs, so no effect was promoted. The bounded
replay used 122 P-code flows across depths zero through six after three stable
callee-before-caller Parameter ID passes. Ghidra emitted CFG/3 for 116
functions and explicitly skipped six whose High-P-code graphs had no block at
the function entry. The closure also contains 59 direct-call targets outside
the exported flow set, and 315 of 320 STORE operations have no exact memory
fact. These missing CFG, target, store, and argument-root facts remain
conservative barriers; the replay is not a complete call closure and does not
validate positive alias filtering. `--skip-missing-entry-blocks` now lets a
batch retain valid CFG rows while logging each skipped entry. The new
`scripts/run_ghidra_parameter_id.sh` persists Parameter ID on a writable
project copy before read-only evidence export. Prior call-root sidecars from
projects whose signatures were not saved must be regenerated before reuse;
the earlier conservative audit statuses do not establish the validity of
those sidecars.

A fresh post-Parameter-ID replay of the `next100g`/`next100h` roots completed
five bounded closures covering 89 unique functions and 12,050 flow rows. Three
callee-before-caller signature passes changed 62 signatures, then 7, then 0.
The first broad caller-root export omitted 29 of 356 closure call arguments:
18 were beyond the 128-caller cap, 8 belonged to self-recursive calls, and 3
were absent from Ghidra's reference index. The caller-argument exporter now
includes call references to the current function and makes `--caller-entry`
decompile the selected caller directly before checking its P-code target. A
new plan `/2` adds a caller address to each plan row, allowing one read-only
Ghidra invocation to scope every closure call without hitting the global cap.
Its replay completed all 271 caller-target-parameter plans and emitted
subtrees for all 356 call arguments; 71 had exact caller-formal/constant-offset
roots, so the rest remain barriers.

The small `next100h` closure for `00a3dda0` is complete across four functions:
all four exported CFG/3, the flow contains 538 operations, and its 63 STOREs
have 50 exact memory locations plus 13 unresolved locations. The exact root
from `00a3dda0` to `009015b0` maps parameter 0 to caller parameter 0 at `+0x98`.
However, four side-effect-dependent `INDIRECT` operations in the callee closure
and 13 unresolved store locations keep all three `/5` pairs at
`possible_intervening_memory_effect`; no alias filtering promotion is supported
by this replay.

The exporter now has an opt-in CFG/4 contract that resolves each Ghidra
`INDIRECT` operation reference to its exact source operation. The Python reader
checks that the source address, sequence time, and opcode identify another
operation in the same function. Interprocedural effects/2 and dominance/6
remove a marker only when that source is independently classified; unresolved
links, aliasing stores, unknown calls, and incomplete evidence remain barriers.
A fresh Ghidra replay exercised the new path: duplicate markers disappeared
from the unknown-effect set, while the field-pair statuses stayed conservative
because possible aliasing stores remained. The consumer retains its raw rows and
measured outcomes.

The generic `GhidraInterproceduralMemoryEffect/1` builder and versioned `/5`
audit are merged in revenginstr PRs [#110](https://github.com/Hanz0Hatt0r1/revenginstr/pull/110)
and [#111](https://github.com/Hanz0Hatt0r1/revenginstr/pull/111). They propagate
only exact caller-formal roots through bounded direct-call graphs, compare
same-root byte ranges under the physical-space contract, and use a finite
monotone fixed point for cycles. Missing argument links, incomplete callee
facts, unresolved stores, indirect calls, unknown operations and exhausted
budgets remain barriers. `/1`–`/4` stay unchanged.

Ghidra screens (`scan25`–`scan27`) exercised the bounded batch
parameter-field exporter on the retail x86-32 SHIFT executable. The function
and call indexes only selected targets; the exporter determined all field and
STORE facts from High P-code. Scan25 sampled 100 of 2,374 eligible functions
and produced eight parameter-field stores, 271 loads, 282 memory STORE facts,
and no exact pair. Scan26 sampled 256 of 561 higher-parameter candidates and
produced 34 stores, 965 loads, 951 memory STORE facts, and eight pairs across
four functions. Its `/6` screen reported six `possible_intervening_memory_effect`
and two `store_not_dominating_load` rows, with no unique candidate. Scan27
screened the remaining 305 functions in that candidate population and
produced 64 stores, 1,302 loads, 1,180 memory STORE facts, and sixteen pairs
across ten functions. `/6` reported five possible effects and eleven
non-dominating stores, again with no unique candidate.

Scan28 sampled 256 midpoint quantiles from 1,713 remaining functions in the
broader one-or-more-parameter, 40–800-byte population. It produced six
parameter-field stores, 583 loads, 848 memory STORE facts, and one exact pair
in `004301a0`. The load at `004301a9` precedes its paired store at `004301b3`,
so `/6` reports `store_not_dominating_load`; there is no `/5` candidate to
replay.

Scan29 sampled 256 midpoint quantiles from the 1,457 functions left in that
broad population. It produced eight parameter-field stores, 689 loads, 991
memory STORE facts, and five pairs in `00458170` and `004d90b0`. The initial
`/6` screen reported four `possible_intervening_memory_effect` pairs and one
`store_not_dominating_load`. A focused replay of the four pairs in `00458170`
captured the exact root for the call at `0045818a` to `0067cbc0`: caller
parameter 0 plus `0xc`. The callee's complete three-operation flow contains
only `COPY`, `CAST`, and `RETURN`, so the interprocedural sidecar classifies
that call as `no_aliasing_memory_effect`. Call-aware `/6` promotes the pair
from store `00458187` to load `004581a7` to one `unique_cfg_store_candidate`;
the other three pairs in that function remain possible because unresolved
memory writes and calls remain on their paths. The fifth pair remains
non-dominating. This is structural evidence, not a claim about branch
feasibility or runtime value flow. Retained exports and replay inputs are in
the [scan29 evidence bundle](evidence/receiver-field-access/nfs-shift-screening-20261019/README.md).

The exact-root scan26 replay for `004d6700` formed two pairs at offset
`0x334`. Five of eleven planned caller-argument slots had exact formal-plus-
offset roots. Across the pairs, interprocedural effects contained six
`unknown_effect` and two `no_aliasing_memory_effect` rows; both `/5` and `/6`
remained `possible_intervening_memory_effect`. A bounded follow-up reached a
`CALLIND` in `0065cd30` under `00637890`, so missing and indirect nested effects
remain barriers.

Scan27's narrowest candidate, `0048e380`, has a dominating `param0 + 0x4` store
at `0048e3b1` and compatible load at `0048e3f2`. Every local intervening STORE
has a complete exact memory fact at a disjoint offset. Its only remaining
witness barrier is the call at `0048e3d5` to `0062e1a0`. The bounded closure
reaches `CALLIND` through `0062e1a0 → 00901179 → 0090a62e`; the caller passes a
constant to the root call and therefore has no formal-root mapping there. With
the same pair, P-code, memory facts and root sidecar, `/5` and `/6` both retain
`possible_intervening_memory_effect` and report zero unique candidates. CFG/4
reduces the relevant call's unknown-operation identifiers from 57 to 27 by
deduplicating linked markers, but the reachable indirect call and missing
nested flows keep the effect unknown. The complete retained selections,
exports, roots, effects, and audits are in the
[scan25–27 evidence bundle](evidence/receiver-field-access/nfs-shift-screening-20261019/README.md).

Scans30–34 exhausted the remaining 1,201 functions in the broad one-or-more-
parameter population: four 256-function midpoint-quantile batches followed by
the final 177 functions. Across these screens, seventeen of nineteen exact
pairs have non-dominating stores. The two remaining pairs stay possible after
focused call-effect replay: scan32's call closure reaches an indirect call and
unknown effect, while scan33's callee has an unresolved STORE destination and
only one exact caller-argument root. Neither case is promoted. Scan35 also
screened the four remaining `this`-only direct-call callers with 40–800-byte
bodies; the read-only exporter found no parameter-rooted field loads or
stores and no P-code STORE facts. See the
[scan25–37 evidence bundle](evidence/receiver-field-access/nfs-shift-screening-20261019/README.md).

Scan36 screened all 295 remaining explicit-parameter functions with
40–800-byte bodies which do not appear as direct-call callers in the pinned
call-edge export. It produced fourteen exact pairs across seven functions;
all stores are non-dominating, so no interprocedural replay is eligible. The
index establishes only that these functions have no outgoing direct-call row
in the selected call-edge export; it does not establish that they are invoked
only indirectly. Scans25–35 and scan36 therefore cover both call-edge
populations within the explicit-parameter, 40–800-byte filter.

Scan37 screened all 161 explicit-parameter functions whose bodies exceed 800
bytes (159 have outgoing direct-call rows and two do not). It produced 39
exact pairs across two functions. `/6` found 33 non-dominating stores, five
possible effects, and one unique candidate; a focused replay made one of the
five possible pairs unique. The replay follows 97 reachable P-code flows and
has CFG/4 for 95 of them. Two CFG boundaries remain (`006642a0` has no entry
block; `0090e864` has multiple entry blocks), as does direct target `006642a5`
outside the pinned function inventory. CFG/4 removed source-linked
`INDIRECT` markers, but 22 reachable `CALLIND` operations in 13 functions
leave four pairs possible. `PointerProvenance/1` classifies the 22 target
expressions as six memory-read anchors, thirteen call barriers, and three
ambiguous results; none resolves to an exact function entry. The receiver-
type exporter matched all 22 sites but recovered only generic primitive
labels, so it adds no target identity evidence. Across scans25–37, three
unique candidates, 20 possible pairs, and 79 non-dominating pairs have been
recorded. See the
[scan25–37 evidence bundle](evidence/receiver-field-access/nfs-shift-screening-20261019/README.md).

The four downstream memory-read anchors now have a generic structural
projection: `IndirectCallPointerSlot/1` identifies aligned pointer-slot access
shapes at `006657ed` (`+0x30`), `00665801` (`+0x8`), `0066582d` (`+0x34`), and
`00665841` (`+0xc`). The exact target addresses remain unknown. A read-only
Ghidra reference export confirms that `006657e0` and `00665820` are reached
from the two wrapper functions, while their receiver comes from the runtime
field at `AptCIH + 0x20`. The field is initialized to zero in `0066ee90` and
copied by `00663f50`; an additional vtable write in `0043c792` is reached from
the cleanup path `0066efc0`, not a new factory. These facts narrow the observed
static construction path but do not bind the runtime field value to a table.

**Next:** trace all exact writes and copy sources for the runtime `+0x20`
field, or acquire bounded runtime evidence for those four receivers. Keep
unknown targets and roots as barriers. The `/6` statuses still need a complete
memory-effect replay, and the CFG gaps at `006642a0` and `0090e864` remain open;
the bounded slice at `006642a5` is not a complete function flow or CFG. Assess
bodies smaller than 40 bytes only if this unresolved set or new pair evidence
gives a concrete reason to extend the population screen. Do not infer alias
facts from decompiler text or instruction-level corpus labels.
