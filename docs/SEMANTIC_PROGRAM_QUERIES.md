# Semantic program queries

`revenginstr-semantic-program-query` applies deterministic selectors to a
`SemanticProgramGraph/1` or `/2` JSONL file and emits one
`SemanticProgramQueryResult/1` record per program graph. Results pin both the
source graph id and the complete input-file SHA-256; matched nodes and edges
keep their original evidence support.

Find indirect call sites and their incident graph edges:

```sh
revenginstr-semantic-program-query program-graphs.jsonl \
  --view exploratory \
  --kind operation \
  --call-target-state indirect \
  --output indirect-calls.jsonl
```

Filter graph records by relation, conflict state, function entry, operation
address, field offset, or a supporting effect/source-record id:

```sh
revenginstr-semantic-program-query program-graphs.jsonl \
  --view exact-only \
  --relation calls \
  --conflict-state contested \
  --output contested-exact-calls.jsonl
```

Repeated selectors within one option are alternatives; different selector
groups are combined. Node selectors return matching nodes and their incident
edges, restricted by any relation selector. A relation-only query returns the
matching edges and their endpoints as matched nodes. `related_nodes` contains
other edge endpoints needed as context, even when they do not match the node
selectors or confidence view; these context nodes are not query matches or
claims accepted by that view.

Views are:

- `exact-only`: select records marked `exact_static`. Contested records remain
  visible with their conflict state.
- `accepted-high-confidence`: select only uncontested records whose recorded
  confidence is non-null and meets `--minimum-confidence` (default `0.95`).
  The query does not calibrate confidence; use this view only when the graph
  producer documents calibration. Current structural graph builders emit
  null confidence, so this view returns no accepted records for their output.
- `exploratory`: keep all graph records, including `exact_static`,
  `derived_structural`, `mixed`, `observed_metadata`, and contested records.

For example, a producer can trace conclusions supported by a known
Effect-IR fact:

```sh
revenginstr-semantic-program-query program-graphs.jsonl \
  --view exploratory \
  --support-id 1134c4c3afc52240eb8c7e7fddc4e38893663a852aded252c771c5b3dd7b86cd \
  --output support-uses.jsonl
```

The query returns graph facts and their incident context. It does not infer
control-flow reachability, field semantics, dispatch targets, callback paths,
or execution order. Those require graph inputs and analysis contracts that
remain under development.
