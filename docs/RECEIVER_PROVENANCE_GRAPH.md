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
consumer is expected to build graphs from existing typed receiver, field-store,
call-argument, and P-code artifacts; bounded interprocedural propagation is a
separate M2.3 step.

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
