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

The `semantic-program-graph` stage can be chained in a pinned benchmark
manifest after `function-effect-ir`, with the receiver TSV declared as an
additional input when used. The schemas cover structural facts and observed
receiver metadata. Receiver dispatch, recovered layouts, roles, states,
resources, callbacks, execution contexts, graph queries, audited consumer gold
subgraphs, and M10 exit criteria remain open work.
