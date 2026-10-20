# Semantic program queries

`revenginstr-semantic-program-query` applies deterministic selectors to a
`SemanticProgramGraph/1`, `/2`, `/3`, or `/4` JSONL file and emits one
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

In `/4`, exact-joined direct-call argument tokens are fields on their source
operation nodes. Select those call sites with the usual function and relation
filters:

```sh
revenginstr-semantic-program-query program-graphs.jsonl \
  --view accepted-high-confidence \
  --kind operation \
  --function-entry 002d2f1c \
  --relation calls \
  --output calls-with-arguments.jsonl
```

The returned nodes keep the ordered P-code value tokens, widths, and row
provenance. The query does not chase `def:` tokens or assign argument semantics;
graph construction can attach the separately validated one-row definition
references described below.
Use `--call-argument-token` to select exact tokens as alternatives. For
example, this selects direct calls with an observed zero argument:

```sh
revenginstr-semantic-program-query program-graphs.jsonl \
  --view exact-only \
  --kind operation \
  --relation calls \
  --call-argument-token const:0x0:4 \
  --output calls-passing-zero.jsonl
```

The token match is literal and retains the whole argument list on each result
node; it does not explain what the value means.

For graphs built with a definition sidecar, select call sites by the resolution
state of any argument. Repeating the option selects any of the listed states:

```sh
revenginstr-semantic-program-query program-graphs.jsonl \
  --view exact-only \
  --kind operation \
  --relation calls \
  --call-argument-definition-state exact_definition \
  --output calls-with-exact-argument-definitions.jsonl
```

The matched call nodes retain the full argument list and its evidence refs. A
graph without definition annotations produces no matches for this selector.
When combined with `--call-argument-token`, both filters must match the same
argument.

For graphs built with an operand-trace sidecar, select call sites by trace
state. Repeating the option selects any listed state:

```sh
revenginstr-semantic-program-query program-graphs.jsonl \
  --view exact-only \
  --kind operation \
  --relation calls \
  --call-argument-trace-state boundary_reached \
  --output calls-with-operand-boundaries.jsonl
```

The matched call nodes retain each argument's state and trace-row reference;
the hash-pinned trace sidecar contains the bounded producer and boundary rows.
When combined with token or definition-state selectors, all argument filters
must match the same argument. Graphs without trace annotations produce no
matches for this selector.

For `/3` and `/4` graphs, layout fields can be selected by type id and byte offset. The
result includes the owning type node as related context:

```sh
revenginstr-semantic-program-query program-graphs.jsonl \
  --view exploratory \
  --kind layout_field \
  --type-id nevergone:opaque-object-002a6584 \
  --field-offset 0x104 \
  --output joystick-field.jsonl
```

Layout candidates retain their review status and source evidence in the node;
the query only selects graph records and does not validate or upgrade a type
candidate.

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
- `accepted-high-confidence`: select only uncontested records whose evidence
  is `exact_static`, or whose numeric confidence is non-null and meets
  `--minimum-confidence` (default `0.95`). Exact static facts do not receive a
  fabricated probability; inferred and structural facts still require
  calibrated confidence. Contested records never pass.
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

## Bounded direct-call paths

`revenginstr-semantic-program-path-query` enumerates simple paths between two
function entries using only `calls` edges and their exact call-site evidence:

```sh
revenginstr-semantic-program-path-query program-graphs.jsonl \
  --source-function-entry 00a45520 \
  --target-function-entry 00886930 \
  --view exact-only \
  --max-hops 12 \
  --output call-paths.jsonl
```

Every path step contains the caller and callee function nodes as context, the
call operation, its `contains` edge, and the exact `calls` edge. The operation
and both edges must pass the selected view. A conflict on either function
endpoint marks the step contested. Contested steps remain visible in
`exact-only` and `exploratory` views.

Optionally supply `--function-pcode-cfg cfg.jsonl` to pin Ghidra
`FunctionPcodeCFG/1`–`/4` evidence. The query joins each call site by exact
function entry, address, P-code time, and opcode, then reports its block and a
successor path from the entry block when the CFG version provides one. A path
status distinguishes entry-reachable call sites, unreachable call sites,
opcode mismatches, incomplete CFG evidence, and paths with no call sites to
check. This is block-graph reachability only; branch predicates and
interprocedural execution are not proven.

```sh
revenginstr-semantic-program-path-query program-graphs.jsonl \
  --source-function-entry 00a45520 \
  --target-function-entry 00a40550 \
  --view exact-only \
  --function-pcode-cfg function-pcode-cfg.jsonl \
  --output call-paths-with-cfg.jsonl
```
The bounded `uncertain_call_frontier` lists unresolved, indirect, or
conflicted call sites in functions reachable from the source through the
selected direct-call edges. Each entry includes its function node, the site's
`contains` edge, and one bounded direct-call witness path to its function; an
empty witness means the site is in the source function. A frontier entry is a
place where the static call graph lacks a unique uncontested target; it does
not establish that the call reaches the requested target function or that the
site blocks a feasible execution path. CFG data annotates call-site block
locations only; path enumeration still uses direct-call edges and does not use
callback hypotheses or inferred dispatch targets.
Search fails without writing a partial result when its path or expansion cap
is exceeded.

The query returns graph facts and their incident context. It does not infer
control-flow reachability, field semantics, dispatch targets, callback paths,
or execution order. Those require graph inputs and analysis contracts that
remain under development.
