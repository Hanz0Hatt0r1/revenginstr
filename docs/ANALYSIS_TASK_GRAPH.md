# Analysis task graph and invalidation plan

`AnalysisTaskGraph/1` describes task-to-task dependencies and the artifact
identifiers each task reads or writes. A task declares a project-neutral
`task_kind`, a hash of its configuration, explicit task dependencies, and
artifact inputs/outputs. The graph stores no executable command or free-form
arguments.

```json
{
  "format": "REVENGINSTR.AnalysisTaskGraph/1",
  "tasks": [
    {
      "task_id": "pcode",
      "task_kind": "pcode_export",
      "configuration_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "depends_on": [],
      "input_artifacts": ["binary"],
      "output_artifacts": ["pcode"]
    },
    {
      "task_id": "callgraph",
      "task_kind": "callgraph",
      "configuration_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "depends_on": ["pcode"],
      "input_artifacts": ["pcode"],
      "output_artifacts": ["calls"]
    }
  ]
}
```

`task_id` and artifact IDs are opaque caller-owned identifiers. A task that
reads an artifact produced inside the graph must directly depend on that
artifact's producer. Producers must be unique, task dependencies must exist,
and the full graph must be acyclic. The planner validates these relationships
and computes a stable topological order.

Plan downstream work after artifact contents change:

```sh
revenginstr-analysis-invalidation-plan task-graph.json \
  --changed-artifact binary \
  --output invalidation-plan.json
```

The `AnalysisInvalidationPlan/1` report pins the input graph hash and gives the
topological order, changed artifact IDs, and invalidated tasks with direct or
upstream causes. If a produced artifact itself changes, its producer stays
valid; consumers of that artifact are invalidated. Invalidation also
propagates through declared task dependencies.

This command only validates and plans. It does not execute analyzers, choose
evidence requests, or decide whether a result should be accepted. The
`analysis-invalidation-plan` stage can run inside a pinned benchmark manifest.

For content-addressed task signatures based on source artifact and
implementation hashes, see [Analysis task cache keys](ANALYSIS_TASK_CACHE.md).
