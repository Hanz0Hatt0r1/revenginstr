# Semantic program graph

`revenginstr-semantic-program-graph` combines a versioned Function Effect IR
file into one graph JSONL record per program:

```sh
revenginstr-semantic-program-graph function-effects.jsonl \
  --output program-graphs.jsonl
```

Pass an optional generic Ghidra receiver export to preserve receiver metadata
and join it to exact indirect-call sites:

```sh
revenginstr-semantic-program-graph function-effects.jsonl \
  --receiver-types indirect-receiver-types.tsv \
  --output program-graphs.jsonl
```

Without receiver input the builder emits `SemanticProgramGraph/1`. With it the
builder emits `/2`, pins the receiver TSV hash, and preserves every receiver
row as a `receiver_observation` node. It joins an observation to a `CALLIND`
only when function entry, call address, and P-code time all match. The
`join_state` distinguishes a successful join, a contested site, an ambiguous
site, a missing function in Effect IR, a missing call site, and a site that is
not indirect. Unjoined observations remain in the graph without a call edge.

Add an optional `TypeLayoutHypothesis/1` JSONL input to emit `/3` and connect
candidate layouts to the same program graph:

```sh
revenginstr-semantic-program-graph function-effects.jsonl \
  --type-layout-hypotheses type-layout-hypotheses.jsonl \
  --output program-graphs.jsonl
```

Every layout row's `program_id` must exactly match an Effect IR program id;
the builder does not infer identity from binary hashes. `/3` pins the layout
artifact hash, adds a `type` node and one `layout_field` node per reviewed
offset, and connects them with `has_field`. Type nodes retain architecture,
object-size evidence, vtable anchors, candidate relationships, and conflicts.
Field nodes retain access evidence, type candidates, and conflicts. These
nodes remain candidate/review data, use null confidence, and stay out of the
accepted-high-confidence view. Explicitly conflicted inputs remain contested.
When both receiver observations and layouts are supplied, `/3` retains both
inputs and joins them independently. Supplying call arguments as well emits
`/4` and retains all three inputs.

Supply an optional `DirectCallArgumentObservation/1` JSONL file to emit `/4`:

```sh
revenginstr-semantic-program-graph function-effects.jsonl \
  --type-layout-hypotheses type-layout-hypotheses.jsonl \
  --call-arguments direct-call-arguments.jsonl \
  --call-argument-definitions direct-call-argument-definitions.jsonl \
  --output program-graphs.jsonl
```

The builder pins the observation-file hash and executable hash. When layouts
are also supplied, their executable hash must agree. It attaches an
argument count, ordered value tokens, widths, observation row index, and the
source P-code reference to an operation only when caller, call address,
P-code time, resolved callee, and the original P-code artifact/row all match.
Unmatched or ambiguous observations fail closed. Argument tokens remain
static observations; `def:` tokens are not resolved here, and constants do
not establish resource names, prototypes, or runtime value flow.

Optionally supply the matching `DirectCallArgumentDefinition/1` JSONL. The
builder verifies each definition row against the pinned call-observation
record, callsite identity, P-code artifact, argument index, token, and width.
It attaches the resolution state and exact definition evidence references to
each argument and pins the definition-analysis artifact hash. This remains a
single-row definition link and does not chase transitive data flow.

This first projection emits program, function, operation, and
parameter-rooted field nodes. It emits `contains` edges for observed program,
function, and operation membership; exact `calls` edges only when a direct
call target is present; and `reads`/`writes` edges for parameter-rooted field
accesses. A `CALLIND` remains an indirect call site with no invented target.
An unresolved direct call remains a call site with `call_target_state` set to
`unresolved`.

Field identity is scoped to the function entry, formal parameter index, and
constant byte offset. The graph does not equate same-offset fields in separate
functions or infer class/object identity. When the same call site has multiple
distinct exact direct targets, all candidate edges are retained and marked
`contested`; no target is silently selected. If independent inputs report
different P-code opcodes for the same function, address, and P-code time,
affected operation and access edges are also marked `contested` with
`opcode_disagreement`.

In `/1`, every node and edge carries source effect ids, evidence classes,
source artifact SHA-256 values, and record ordinals. In `/2`, receiver
observations carry the receiver TSV's SHA-256 and record ordinal. `confidence`
is null because these inputs are not calibrated probabilities. Graph identity
and ordering are deterministic; the graph pins each input artifact's hash.
`observes_receiver` edges exist only for exact `CALLIND` joins. The receiver
strings are decompiler type metadata; they do not establish a class, dispatch
slot, or target. No `dispatches` edge is inferred.

The `accepted-high-confidence` view admits uncontested `exact_static` facts
without assigning them a numeric confidence. Other evidence classes still
need a calibrated score at the requested threshold; contested records never
pass. This separates exact static facts from confidence estimates.

The `semantic-program-graph` stage can be chained in a pinned benchmark
manifest after `function-effect-ir`, with receiver TSV and layout JSONL inputs
declared when used. `/3` connects candidate layouts but does not infer object
identity from function-local fields or promote candidate type/layout labels
to accepted facts. Receiver dispatch, roles, states, resources, callbacks,
execution contexts, and CFG-feasible path/reachability queries remain open.
Narrow structural gold and projection audits now report 1.0 precision for
55 accepted direct-call edges across five frozen subgraphs. Derived field
edges remain review-only; broadly scoped semantic subsystem gold and the M10
exit criteria remain open. See [graph evaluation replays](evidence/semantic-program-graph-evaluation/README.md).
The deterministic graph selector and its three evidence views are documented in
[Semantic program queries](SEMANTIC_PROGRAM_QUERIES.md), including the bounded
direct-call path query. These call-graph paths do not establish CFG-feasible
execution reachability.

Consumer-owned subgraphs can be scored with the scoped
[`SemanticProgramGraphGold/1` evaluator](SEMANTIC_PROGRAM_GRAPH_EVALUATION.md).
GT5 and the NFS call-path replay remain raw P-code projection audits.
Nevergone and NFS M2.3 now provide narrow consumer-owned structural gold;
they do not yet establish broad subsystem semantics or accepted precision for
derived field relations.
