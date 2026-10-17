from pathlib import Path

path = Path("docs/ROADMAP.md")
text = path.read_text(encoding="utf-8")


def replace_once(old: str, new: str) -> None:
    global text
    count = text.count(old)
    if count != 1:
        raise SystemExit(f"expected exactly one occurrence, got {count}: {old[:100]!r}")
    text = text.replace(old, new, 1)


replace_once(
    "**Repository baseline:** `main` through `af59da68df3b34e2d3c56ff759c7858d2d49b082`",
    "**Repository baseline:** `main` through `d918e9319ce0773e16f692a4dac1cdc92a1561e2`",
)
replace_once(
    "**Scope:** project-neutral reverse-engineering analysis infrastructure: evidence extraction, indirect-dispatch recovery, receiver/type/vtable inference, ML classification, selective routing, semantic inference, orchestration, validation, and reusable interfaces.",
    "**Scope:** project-neutral reverse-engineering analysis infrastructure: evidence extraction, indirect-dispatch recovery, receiver/type/vtable inference, ML classification, selective routing, semantic inference, orchestration, validation, whole-program type/layout recovery, bounded hybrid static/dynamic analysis, semantic program graphs, feedback-driven learning, architecture/ABI expansion, decompiler/recompiler integration, and reusable interfaces.",
)

replace_once(
    "9. machine-readable artifacts consumable by decompilation/recompilation projects.\n",
    "9. machine-readable artifacts consumable by decompilation/recompilation projects;\n"
    "10. a whole-program recovered model of function signatures, object layouts, ownership/lifetime and type relationships where evidence supports them;\n"
    "11. a provenance-linked semantic program graph connecting functions, objects, fields, states, resources, callbacks and execution contexts;\n"
    "12. optional reversible suggestion bundles that can safely project accepted analysis back into decompiler and recompilation workflows.\n",
)

replace_once(
    "- stronger cross-project validation.\n",
    "- stronger cross-project validation;\n"
    "- whole-program signature, type and object-layout recovery;\n"
    "- bounded static/dynamic evidence acquisition for cases static analysis cannot resolve;\n"
    "- a unified semantic program graph above per-function summaries;\n"
    "- a leakage-safe reviewer-feedback-to-training loop;\n"
    "- architecture/ABI expansion beyond the initial ARM32/x86-32 consumers;\n"
    "- safe decompiler/recompiler apply-back of accepted results.\n",
)

replace_once(
    "| Non-Nevergone validated consumers | 1 early consumer (NFS Shift) | >=2 | >=3 |\n",
    "| Non-Nevergone validated consumers | 1 early consumer (NFS Shift) | >=2 | >=3 |\n"
    "| High-confidence recovered-layout audit acceptance | not canonical yet | >=90% | >=95% |\n"
    "| Decisive bounded probe rate on planner-selected unresolved cases | not canonical yet | >=50% | >=70% |\n"
    "| Semantic graph accepted-edge precision | not canonical yet | >=0.95 | >=0.98 |\n"
    "| Validated ISA/ABI combinations | ARM32 + early x86-32 consumers | >=4 | >=5 |\n",
)

replace_once(
    "| M7 | P1/P2 | Cross-project productization | Stable reusable pipeline across multiple consumers |\n",
    "| M7 | P1/P2 | Cross-project productization | Stable reusable pipeline across multiple consumers |\n"
    "| M8 | P1 | Whole-program type/layout recovery | Evidence-backed signatures, object layouts and lifetime relationships |\n"
    "| M9 | P1 | Hybrid static/dynamic analysis | Bounded probes resolve high-value static ambiguities with provenance |\n"
    "| M10 | P1 | Semantic Program Graph | Unified evidence-linked model of program entities and relationships |\n"
    "| M11 | P1/P2 | Active learning and feedback loop | Reviewed feedback can improve models without contaminating evaluation |\n"
    "| M12 | P2 | Architecture/ABI expansion | Shared core validated across ARM64, x86-64 and PowerPC-class targets |\n"
    "| M13 | P2 | Decompiler/recompiler integration | Accepted results can be safely projected back into analysis workflows |\n",
)

new_milestones = r'''# 13. M8 — Whole-program type and layout recovery

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
'''

marker = "# 13. Evaluation and CI matrix\n"
if marker not in text:
    raise SystemExit("evaluation marker missing")
text = text.replace(marker, new_milestones + "\n# 19. Evaluation and CI matrix\n", 1)

for old, new in [
    ("# 14. Data and label strategy", "# 20. Data and label strategy"),
    ("# 15. PR-sized implementation sequence", "# 21. PR-sized implementation sequence"),
    ("# 16. Recommended execution order", "# 22. Recommended execution order"),
    ("# 17. Definition of done", "# 23. Definition of done"),
    ("# 18. Major risks", "# 24. Major risks"),
    ("# 19. Success states", "# 25. Success states"),
    ("# 20. Immediate next action", "# 26. Immediate next action"),
]:
    replace_once(old, new)

replace_once(
    "| Semantic audit set | role/claim quality | M5+ |\n| Cross-project holdout | transfer | M7/release |\n",
    "| Semantic audit set | role/claim quality | M5+ |\n"
    "| Type/layout gold fixtures | signatures, fields, lifetime relationships | M8+ |\n"
    "| Bounded hybrid replay | static/runtime correlation and probe value | M9+ |\n"
    "| Semantic graph audit | accepted relation precision/provenance | M10+ |\n"
    "| Feedback promotion audit | leakage/adjudication/model lineage | M11+ |\n"
    "| Cross-architecture parity | normalized evidence portability | M12+ |\n"
    "| Apply-back round trip | safe reversible decompiler integration | M13+ |\n"
    "| Cross-project holdout | transfer | M7+/release |\n",
)

replace_once(
    "5. Once a frozen set materially influences a new rule/threshold, retire it as the final untouched test and create a new sealed holdout.\n",
    "5. Once a frozen set materially influences a new rule/threshold, retire it as the final untouched test and create a new sealed holdout.\n"
    "6. Keep reviewer feedback quarantined until explicit adjudication, family/duplicate checks and frozen-set leakage checks complete.\n"
    "7. Preserve model-generated hypotheses as hypotheses; pseudo-labels never become human ground truth by provenance erasure.\n"
    "8. Version recovered type/layout and semantic-graph gold data separately from model predictions so later corrections remain auditable.\n"
    "9. Cross-architecture evaluation must separate architecture transfer from project/domain transfer.\n",
)

p2_tail = '''## P2 — autonomy and transfer

22. Bounded evidence request planner.
23. Human review feedback format.
24. Cross-project holdout harness.
25. Distribution-shift report.
26. Stable top-level analysis CLI/result schema.
27. Release-grade documentation and compatibility policy.
'''
p34 = p2_tail + r'''

## P3 — whole-program recovery and active evidence

28. Function prototype hypothesis schema and compatibility evaluator.
29. Object/type layout hypothesis schema and synthetic fixtures.
30. Allocation/lifetime/ownership evidence projection.
31. Bounded runtime probe-request and correlation contracts.
32. Static/runtime differential replay and information-gain metrics.
33. Semantic Program Graph schema and deterministic builder.
34. Gold-subgraph evaluation harness.
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
'''
replace_once(p2_tail, p34)

wave_f = '''### Wave F — transfer/productization

M7: multiple independent consumers, drift handling, stable interfaces, project-adapter guide and release benchmark workflow.
'''
waves = wave_f + r'''

### Wave G — whole-program reconstruction

M8: signatures, object layouts, field types, ownership/lifetime and independently audited type hypotheses.

### Wave H — active evidence and program model

M9 + M10: bounded static/dynamic evidence acquisition followed by a provenance-linked Semantic Program Graph. Dynamic evidence remains consumer-controlled and graph conflicts remain explicit.

### Wave I — learning loop

M11: reviewer-feedback quarantine, adjudication, leakage-safe retraining and promotion/rollback gates. No feedback enters training merely because a reviewer touched it.

### Wave J — architecture and workflow integration

M12 + M13: validate the normalized core across ARM64, x86-64 and PowerPC-class targets, then project accepted results back into decompiler/recompiler workflows through reversible apply bundles.

At the end of Wave J, `revenginstr` should qualify as a multi-architecture autonomous reverse-engineering analysis platform rather than only an assisted-analysis toolkit.
'''
replace_once(wave_f, waves)

replace_once(
    "10. downstream consumers can distinguish exact, inferred and learned evidence.\n",
    "10. downstream consumers can distinguish exact, inferred and learned evidence;\n"
    "11. architecture-specific behavior is isolated below a documented normalization boundary when the feature is intended to transfer;\n"
    "12. any active/runtime action is bounded, caller-approved and replayable from captured evidence;\n"
    "13. any apply-back mutation is dry-runnable, conflict-aware, reversible and provenance-linked.\n",
)

risk_anchor = '''### Larger models hide structural weaknesses

Mitigation: preserve heuristic/sparse baselines, feature ablations and evidence-linked structured outputs.
'''
new_risks = risk_anchor + r'''

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
'''
replace_once(risk_anchor, new_risks)

autonomous = '''## Autonomous-analysis milestone

- >=65% of supported frozen tasks resolve automatically;
- critical wrong accepts <2%;
- conflicts reliably escalate;
- full evidence/decision chain is replayable;
- at least two non-Nevergone consumers have measured transfer behavior.
'''
expanded_success = autonomous + r'''

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
'''
replace_once(autonomous, expanded_success)

path.write_text(text, encoding="utf-8")
