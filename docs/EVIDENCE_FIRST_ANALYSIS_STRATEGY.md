# Evidence-first analysis development strategy

**Status:** proposed execution strategy for future development (not an implementation report)
**Established:** 2026-10-19
**Scope:** generic analysis in `revenginstr`; consumers retain their own binaries, labels, runtime traces, ground truth and game-specific semantics.
**Related roadmap:** [ROADMAP.md](ROADMAP.md), particularly M2–M6 and later M8–M10.
**Reference consumer:** [Nevergone frozen unseen500-v10 receiver coverage](https://github.com/Hanz0Hatt0r1/nevergone-recomp/blob/main/docs/evidence/frozen-unseen500-v10-receiver-coverage/README.md).

## Decision

Future development should prioritize **recovering missing verifiable evidence** over multiplying exporters, expanding unvalidated scans, or tuning a classifier around incomplete evidence.

The default sequence is:

1. Measure exactly what is missing and why.
2. Acquire additional, bounded Ghidra/P-code evidence.
3. Recover pointer/value provenance without inventing types.
4. Build conservative interprocedural memory and call-effect summaries.
5. Use verified evidence to improve receiver/vtable resolution.
6. Evaluate ML and selective routing on independently frozen data.
7. Connect successful stages through a bounded, auditable analysis executor.
8. Extend to semantic roles, whole-program layouts and a semantic program graph only after the supporting evidence is validated.

The milestones in [ROADMAP.md](ROADMAP.md) remain in force. This document specifies **implementation order and gates**, not a declaration that the planned capabilities already exist.

## Baseline and measurement corrections

The current Nevergone identity-disjoint 500-function holdout reports:

| Measurement | Result | Meaning |
| --- | ---: | --- |
| Functions with a receiver query | 100/500 (20.0%) | Query availability across frozen functions |
| Unique-vtable resolutions | 66/203 (32.5%) | Resolution **among existing receiver queries** |
| Functions with >=1 unique-vtable query | 53/500 (10.6%) | Function-level resolved-query coverage |
| Unresolved receiver class | 76/203 | Receiver inference could not identify one class |
| Receiver not single pointer | 61/203 | Current inference cannot treat the observed operand as a single object pointer |
| Dispatch-slot evidence / runtime validation | 0 in this holdout | Not evidence of exact dispatch targets |

The denominator matters. **10.6% is not a semantic precision score**. A function with no virtual dispatch does not necessarily need a receiver. Resolving every currently exported query can cover at most the 100/500 queried functions; increasing whole-population coverage also requires discovering and exporting additional eligible cases. The 500-function set has no independent semantic labels, so no receiver accuracy claim follows from these counts.

Maintain separate, non-interchangeable KPI families:

- **Acquisition:** analyzed-function count, decompilation failures, functions with `CALLIND`, discovered call sites, sites with expression evidence, truncation and export gaps.
- **Eligibility:** confirmed virtual sites vs confirmed other indirect sites vs unknown; measure virtual-call recall only against a manually adjudicated site inventory.
- **Resolution:** unique-vtable queries / eligible or all queries, per-function resolved coverage, dispatch slot and target evidence, abstention reasons.
- **Correctness:** independently adjudicated exact-vtable/slot/target matches and contradictions, zero regression of existing exact witnesses.
- **Performance:** runtime, memory, export size and reproducibility under pinned inputs.

Avoid conflating `CALLIND` with a virtual call. A `CALLIND` first argument may be a receiver candidate, not evidence that a method dispatch exists. In particular, a raw count of functions with queries is **not** the denominator for virtual-call accuracy.

## Phase A — Stabilize the baseline and complete evidence coverage

**Existing work:** [revenginstr PR #147](https://github.com/Hanz0Hatt0r1/revenginstr/pull/147) extends exact caller-formal roots and signed byte offsets. It remained open when this strategy was written; no completed full-suite validation should be assumed.

### A1. Stabilize the caller-root groundwork

- Complete full unit/schema/parity tests for #147 and review the consumer replays before merging.
- Retain a regression for loop-carried `MULTIEQUAL` alternatives that change offsets; never publish a single exact root from such values.
- Preserve bounded caller selection, completion-marker checks and clear truncation reasons.
- Distinguish `Parameter ID` recovery on a controlled, writable **copy** of a Ghidra project from read-only evidence extraction; pin the resulting project revision.

**Gate:** complete tests and at least one pinned real-consumer replay; zero changes to previously confirmed exact outcomes without explanation.

### A2. Add a program-wide `CALLIND` inventory

Create an auditable `CallindInventory` contract and reader/adapter over existing High-P-code flow and indirect-call evidence. It should enumerate call sites and preserve program/function/call address+time, provenance, source hashes, extraction state, and bounded expression status.

At each site record **observations**, not premature semantic conclusions:

- `virtual_candidate` only with a documented vptr/vtable-shaped chain;
- `other_indirect_candidate` only with supporting evidence;
- `unknown` for missing or ambiguous shape;
- explicit `no_pcode`, `decompile_failed`, `truncated` and similar acquisition failures.

The inventory must not depend on a previously inferred receiver class. Compare its `CALLIND` counts to a canonical P-code population, accounting explicitly for decompiler failures and functions not exported.

**Gate:** on the pinned 500-function holdout, every in-scope successful P-code export is counted and reconciled; unsupported cases remain visible, not silently omitted. Record independent reviewer labels for a small stratified set before reporting any virtual-call recall.

## Phase B — PointerProvenance: bounded structural value flow

Add a standalone, project-neutral `PointerProvenance` module; do **not** silently broaden `receiver.infer` into a type oracle. Analyze exact P-code def-use relationships and emit alternative structural roots with source-operation provenance.

Start with:
- `COPY`, `CAST` and width-preserving, justified conversions;
- `PTRADD`, `PTRSUB`, and bounded `INT_ADD` with provable constant byte offsets;
- `MULTIEQUAL`: merge identical roots; preserve a bounded set of distinct alternatives; otherwise mark ambiguous;
- `LOAD`: create a *memory-read anchor* and associated address expression, **not** an assumed object identity or a proven stored value;
- `INDIRECT`: distinguish explicit pure/known cases from side-effect-dependent unknowns; do not discard effect uncertainty;
- cycles, integer overflow, pointer-width mismatch, unknown userops and exhaustion: fail closed.

A candidate should retain `(program, function, operation, root, signed_offset, transformation_path, evidence_refs, status)` and its address-space/pointer-width context. Root kinds may include function parameter, global/address anchor, or unknown. Arbitrary registers are not automatically formal parameters. Join to existing formal-root exports only by exact, pinned keys. Never join by class-name resemblance or same numeric offset alone.

**Gate:** synthetic tests for positive constant offsets, negative offsets, dynamic indices, PHI alternatives, cycles, overflow, width mismatch, `INDIRECT` barriers, and unrooted `LOAD`; same-input real-consumer replay where newly resolved *structural* paths are counted separately from proven class/vtable identities.

## Phase C — Interprocedural call and memory effects

Extend the existing bounded call-result/parameter-load and dominance work rather than replacing it. Build `CallEffectSummary` facts per function with exact evidence lineage:

- known writes, reads, may-write or unknown effects;
- formal-parameter rooted byte ranges when proven;
- direct callee summaries and recursion/SCC handling under finite depth/work budgets;
- unknown indirect calls, external calls, missing callee flow and side-effect-dependent operations stay `may_write` or `unknown`.

Resolve bottom-up where possible, with monotone conservative fixed-point updates for recursive components. Make side effects attributable to exact operation keys; never treat missing flow as purity.

For store/load value-flow promotion, require all-path store dominance, compatible memory-space and access widths, proven alias relationships, absence of an unmodeled interfering write on **all relevant paths**, and a complete consumer replay. A `unique_cfg_store_candidate` is a structural candidate, **not** a proven runtime reaching definition.

**Gate:** verified synthetic aliases and disjoint ranges, unknown-call and recursive-call negative tests; at least one independently reviewed positive consumer case without regressing currently unresolved/exact statuses. If no positive case exists, publish that negative result rather than loosening policy.

## Phase D — Receiver, vtable, slot and layout hypotheses

Combine PointerProvenance with existing receiver graphs, catalog matches, ARM32 vtable-slot evidence and optional exact runtime witnesses. Maintain distinct output levels:

1. exact structural flow between P-code operations;
2. possible receiver/class candidates;
3. uniquely supported vtable identity;
4. uniquely supported dispatch slot/target with ABI-specific proof;
5. optional consumer-verified runtime corroboration.

Missing slot evidence may still permit a useful receiver hypothesis, but must not become an exact virtual target. ABI-specific vptr layouts and constructor writes need independent validation; avoid assuming that x86-32 follows the ARM32 Itanium export contract.

**Gate:** on frozen unseen data, increase eligible-query coverage and useful structural evidence while exact mismatches remain zero on independently labeled checks. The roadmap's >=35% receiver target requires an explicitly pinned denominator and cannot be met by redefining `CALLIND` as virtual dispatch.

## Phase E — Evidence-driven ML, router and semantic roles

Only after the new evidence contracts have synthetic and consumer parity tests:

- Compare baseline P-code-only, callgraph, receiver, memory/effect and combined feature sets using **paired family-disjoint ablations**.
- Keep project/function identifiers, class names, raw addresses and labels out of portable ML features.
- Target the roadmap classifier gate (macro-F1 >=0.80; `game` precision >=0.70 and recall >=0.65) without unexplained class regressions.
- Freeze an **independent labeled router gate** disjoint from calibration by identity and family. The existing v10 crossfit numbers (precision 0.97301, coverage 0.560759) are *not* that gate.
- Preserve router fail-closed behavior: disagreements, OOD, evidence conflict, incompatible schema and missing inputs become review/escalation.
- Train semantic-role models only from adjudicated consumer labels; output role hypotheses and evidence-backed structural summaries as separate artifacts.

**Gate:** independent router accepted precision >=0.970, coverage >=0.55, critical false-accept <1%, no accepted detected evidence conflicts; semantic role scores only on family-isolated labeled holdouts. Unlabeled data must never be counted as accuracy.

## Phase F — Bounded autonomous analysis executor

The existing task graph, invalidation plan, cache, request planner and decision ledger are **building blocks, not yet a complete autonomous execution loop**. Add an executor that:

1. receives an unresolved bounded task;
2. lists missing proof obligations;
3. selects an allowlisted evidence action by expected benefit/cost;
4. invokes an approved read-only exporter or reads a verified cache entry;
5. recalculates affected evidence and hypotheses;
6. terminates as `accepted_exact`, `accepted_high_confidence`, `review_required`, `escalated_conflict`, `unsupported`, or `budget_exhausted`.

Pin task graph, source artifact and project hashes. Use explicit depth/time/size limits, finite iterations, reason codes, and dependency-aware cache invalidation. Do not synthesize arbitrary executable runtime probes. Dynamic observations are optional consumer-controlled evidence, not automatic confirmation of every static hypothesis.

**Gate:** first replay 10 independently chosen, ambiguous indirect-call tasks with complete ledgers; count safe resolutions, abstentions, costs and false accepts. Then assess the roadmap goal of >=65% supported-task resolution on a larger frozen, adjudicated population. Never optimize coverage by hiding unresolved cases.

## Phase G — Semantic graph and safe integration

Once C–F are validated, extend the Effect IR to supported control/data effects, review-based role labeling, type/layout relationships and a provenance-linked semantic program graph. Decompiler/recompiler integration should default to *reversible suggestions*, never overwrite stronger human/debug information, and retain undo manifests. Whole-program conclusions require cross-function evidence and consumer review.

## Recommended PR sequence

| Order | Suggested change | Blocked by | Proof to attach |
| --- | --- | --- | --- |
| 0 | Finish and validate caller-root PR #147 | None | Full tests, negative PHI regressions, consumer replay |
| 1 | `CALLIND` inventory + acquisition/eligibility metrics | Stable baseline | 500-function reconciliation, reviewable classification examples |
| 2 | `PointerProvenance/1` and bounded constant-offset/PHI solver | Inventory contract | Schema, synthetic positive and negative fixtures, consumer replay |
| 3 | Conservative interprocedural call/memory summaries | Pointer roots and complete flows | SCC/call-barrier tests, exact replay and documented abstentions |
| 4 | Vtable/slot evidence joins + receiver evaluation | Provenance, consumer catalogs | Zero exact mismatch, query and eligible-function metrics |
| 5 | ML ablations + independently labeled router gate | New evidence vetted | Pinned cross-project/family-disjoint metrics |
| 6 | Allowlisted autonomous evidence executor | Stable stage contracts | End-to-end 10-case replay and deterministic ledgers |
| 7 | Semantic role, layout, graph and reversible apply-back | Validated C–F | Reviewed gold cases, provenance precision, undo tests |

No PR should claim a completed milestone from tests on a synthetic fixture alone. All behavior-changing PRs should include before/after aggregate KPI deltas, artifact hashes and at least one explicit failure/abstention example. Do not retire consumer compatibility exporters until same-input parity and caller review are complete.

## Repository boundaries and non-goals

- `revenginstr`: generic algorithms, architecture-aware adapters, output formats, schemas, tests, benchmark and executor contracts.
- Nevergone, NFS Shift and future consumers: binaries, P-code exports, runtime probes, class/vtable catalogs, reviewed labels and title-specific interpretation.
- No hardcoded game names, addresses, object offsets or title-derived semantics in generic inference.
- Do not replace Ghidra, claim full decompilation from a structural summary, or use router confidence as a substitute for proof.
- Do not run giant unguided scans while unresolved acquisition/completeness gaps remain unmeasured.
- Optimize in order: **soundness → visibility of unknowns → reproducibility → useful coverage → speed**.

## Planning and review rule

Future work should be selected against this phase order and the [roadmap](ROADMAP.md). A deviation is acceptable only with a written reason, the evidence gap it addresses, and a measurable gate. Progress reports should list **implemented**, **synthetically verified**, **consumer replayed**, and **independently validated** separately; planned work must never be reported as delivered.
