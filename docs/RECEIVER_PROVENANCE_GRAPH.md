# Receiver provenance graph

`REVENGINSTR.ReceiverProvenanceGraph/1` is the project-neutral graph contract
for receiver and object-flow evidence. A JSONL record contains one graph, with
graph-local node and edge ids. The [schema](../schemas/receiver-provenance-graph-v1.schema.json)
defines node kinds, directed relations, evidence classes, and source references.

Nodes represent generic program entities or flow points such as parameters,
field loads/stores, returns, PHIs, globals, constructors/factories, singleton
instances, vtable writes, and indirect calls. Edges represent a directed
relationship between two nodes. Every edge names its evidence class and one or
more `(source_format, source_id)` references. Reusing a source reference across
edges identifies shared evidence; consumers should not count those edges as
independent support.

`graph_id`, node ids, and provenance source ids are opaque join keys. The schema
does not contain a class catalog, semantic label, address convention, or
game-specific interpretation. Those remain in consumer-owned evidence and
artifacts. The v1 schema validates record shape; `validate_graph_references`
checks graph-local id uniqueness and rejects dangling endpoints.

The graph is descriptive evidence only. It does not resolve receiver classes,
infer dispatch slots, transfer call targets, or affect routing. Builders
project typed receiver-call anchors and bounded argument/load/store
relationships. Recursive interprocedural propagation and store-to-load value
flow remain follow-up work.

The initial `revenginstr-receiver-graph` command projects
`GhidraIndirectReceiverType/1` rows into call-anchor graphs. It emits a graph
only when `receiver_present` is `1`; rows with `0` are counted and omitted.
The emitted `receiver_at_call` edge records the observed receiver-to-call
relationship, not a receiver type or class conclusion. The original TSV remains
the source for those facts. Output graphs sort by opaque graph id. Duplicate
call keys, invalid presence flags, and unknown input formats fail closed.

```sh
revenginstr-receiver-graph receiver-types.tsv --output receiver-graphs.jsonl
```

The bounded direct-call exporter can also be projected into one-hop actual
argument-to-formal-parameter edges:

```sh
revenginstr-receiver-argument-flow caller-argument-subtree.tsv \
  --output argument-flow-graphs.jsonl --max-graphs 10000
```

Only root rows (`edge_kind=root`, `depth=0`) become edges. Summary and descendant
rows are counted and skipped. Duplicate roots, malformed keys, unsupported row
formats, and exceeding the graph budget fail closed. This does not recursively
propagate through callees, interpret argument types, or combine distinct input
artifacts; it preserves one exact static call-argument relation per graph.
If a root value is directly defined by `CALL` or `CALLIND`, the graph also
records a generic call-result-to-argument edge from the same source row. It
does not classify that call as a factory/getter or infer its target semantics.

Parameter-to-parameter field-store evidence can be anchored with an explicit
program join key:

```sh
revenginstr-receiver-store-flow parameter-stores.tsv \
  --program-id 'consumer:analysis-id' --output parameter-store-graphs.jsonl
```

Each graph has one store node, a destination-parameter-to-store edge, and a
stored-value-parameter-to-store edge. Both edges point to the same source row,
so they are correlated parts of one STORE observation. The field offset and
numeric parameter indices remain auditable in the source row and are not given
class semantics; the opaque graph id is only a join key. No field-to-load join
or class/type claim is made.

## Joining caller arguments to stores

`revenginstr-receiver-argument-store-flow` joins caller roots to parameter
stores only when the caller row's `callee_entry` exactly matches the store
row's `function_entry` and `parameter_index` matches the stored formal
parameter. Both inputs must belong to the selected program named by the
consumer-supplied program id; the output retains both source records on their
respective edges. It never joins by function name, field offset alone, or
guessed receiver type.

```sh
revenginstr-receiver-argument-store-flow caller-argument-subtree.tsv \
  parameter-stores.tsv --program-id 'consumer:analysis-id' \
  --output argument-store-flow.jsonl --max-graphs 10000
```

Each output graph preserves the actual-argument-to-formal edge and attaches
the matched formal to a field-store node as destination, stored value, or both.
The field offset remains in the source artifact referenced by provenance.

Caller roots can also be joined to parameter-rooted loads:

```sh
revenginstr-receiver-argument-load-flow caller-argument-subtree.tsv \
  parameter-loads.tsv --program-id 'consumer:analysis-id' \
  --output argument-load-flow.jsonl --max-graphs 10000
```

This exact join uses only callee/function entry and formal parameter index.
Each graph records the caller argument, matched formal, and a field-load event
with provenance from both input artifacts. The load offset and result token
remain in the referenced load row. This describes a read through the passed
parameter; it does not establish that a separately observed store reaches the
same object or field.

Same-function parameter field accesses can be grouped when the formal
parameter and numeric field offset match:

```sh
revenginstr-receiver-field-access-pairs parameter-stores.tsv \
  parameter-loads.tsv --program-id 'consumer:analysis-id' \
  --output field-access-pairs.jsonl --max-graphs 10000
```

Each graph retains the store and load source rows on separate edges from their
shared parameter node. Function entry, parameter index, and numeric offset
must all match. A pair records compatible access locations only: it does not
assert instruction order, execution-path compatibility, or that the store
reaches the load as a value.

Parameter-rooted loads can also be traced through P-code data dependencies to
function returns:

```sh
revenginstr-receiver-load-return-flow parameter-loads.tsv \
  function-pcode-flow.tsv --program-id 'consumer:analysis-id' \
  --output load-return-flow.jsonl --max-graphs 10000
```

The builder requires each load token to match a `LOAD` definition in the
P-code artifact, follows output/input tokens to `RETURN`, and retains the
matching P-code rows as provenance. Its `return_flow` edge shows structural
data dependence only; it does not classify the function as a getter or assert
a runtime path or returned semantic role. Call outputs are treated as barriers,
and an `INDIRECT` reference operand is not treated as the copied value.

Call-result values can be traced to function returns with:

```sh
revenginstr-receiver-call-return-flow function-pcode-flow.tsv \
  --program-id 'consumer:analysis-id' --output call-return-flow.jsonl \
  --max-graphs 10000
```

The builder starts only at `CALL`/`CALLIND` operations with an explicit output,
follows P-code output/input dependencies to `RETURN`, and retains every row on
the selected path as provenance. It reports generic `return_flow` evidence;
callee names and this structural relation alone do not establish factory or
constructor semantics.

Exact caller-formal roots can be propagated backward across a supplied set of
callee plans:

```sh
revenginstr-receiver-argument-propagate caller-argument-subtree.tsv \
  caller-parameter-roots.tsv --target-entry 00401000 \
  --target-parameter-index 0 --program-id 'consumer:analysis-id' \
  --output argument-propagation.jsonl --max-depth 8 --max-edges 10000
```

The sidecar row must match an exact root in the subtree artifact. The builder
walks only direct caller-formal to callee-formal flows and preserves both
source rows on each edge. Depth/edge overflow fails; the output describes only
the caller plans supplied to it and does not promote derived expressions,
names, or guessed aliases into parameter roots.

## Minimal example

```json
{
  "format": "REVENGINSTR.ReceiverProvenanceGraph/1",
  "graph_id": "synthetic:receiver-flow",
  "nodes": [
    {"id": "parameter0", "kind": "parameter"},
    {"id": "call0", "kind": "indirect_call"},
    {"id": "receiver0", "kind": "receiver"}
  ],
  "edges": [
    {
      "id": "edge0",
      "from": "parameter0",
      "to": "receiver0",
      "relation": "data_flow",
      "evidence_class": "derived_structural",
      "provenance": [
        {
          "source_format": "REVENGINSTR.GhidraFunctionPcodeFlow/1",
          "source_id": "sample:1000#op0"
        }
      ]
    },
    {
      "id": "edge1",
      "from": "receiver0",
      "to": "call0",
      "relation": "receiver_at_call",
      "evidence_class": "exact_static",
      "provenance": [
        {
          "source_format": "REVENGINSTR.GhidraIndirectCallEvidence/1",
          "source_id": "sample:1000#call0"
        }
      ]
    }
  ]
}
```
