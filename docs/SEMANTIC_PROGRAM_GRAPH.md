# Semantic program graph

`revenginstr-semantic-program-graph` combines a versioned Function Effect IR
file into one `REVENGINSTR.SemanticProgramGraph/1` JSONL record per program:

```sh
revenginstr-semantic-program-graph function-effects.jsonl \
  --output program-graphs.jsonl
```

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
`contested`; no target is silently selected.

Every node and edge carries source effect ids, evidence classes, source
artifact SHA-256 values, and record ordinals. `confidence` is null because the
structural inputs are not calibrated probabilities. Graph identity and
ordering are deterministic; the record also pins the exact Effect IR file
hash. The `semantic-program-graph` stage can be chained in a pinned benchmark
manifest after `function-effect-ir`. The schema covers this initial structural
slice. Receiver dispatch, recovered types/layouts, roles, states, resources,
callbacks, execution contexts, graph queries, and audited consumer gold
subgraphs remain open M10 work.
