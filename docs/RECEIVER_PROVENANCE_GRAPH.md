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
infer dispatch slots, transfer call targets, or affect routing. The first
builder projects typed receiver-call anchors. Joining field-store,
call-argument, and P-code artifacts remains follow-up work; bounded
interprocedural propagation is a separate M2.3 step.

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
