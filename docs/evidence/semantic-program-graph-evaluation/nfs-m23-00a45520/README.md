# NFS M2.3 semantic graph replay

This replay uses the NFS consumer-owned gold subgraph in
[PR #2099](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2099)
at commit [`f165ca7e9c9bfb0e4b1dcfb1a05543ec42d7bd40`](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/commit/f165ca7e9c9bfb0e4b1dcfb1a05543ec42d7bd40).
The scope covers `FUN_00a45520` and `FUN_00a40550`: seven direct calls, two
parameter-0 reads at offset `0x0`, and one parameter-0 write at offset `0x0`.

The NFS consumer evidence describes a conservative structural audit. This
replay does not infer field meaning, prove that the store reaches either load,
establish aliasing or branch feasibility, or claim runtime execution.

## Evaluation

The evaluator uses the `exploratory` view because the field-access edges are
`derived_structural` rather than `exact_static`.

| Relation | Gold | Matched | Precision | Recall |
| --- | ---: | ---: | ---: | ---: |
| `calls` | 7 | 7 | 1.0 | 1.0 |
| `reads` | 2 | 2 | 1.0 | 1.0 |
| `writes` | 1 | 1 | 1.0 | 1.0 |

Unsupported edge rate is 0%; provenance completeness is 100%. Accepted-edge
precision is `null` because confidence is uncalibrated.

## Query replay

`revenginstr-semantic-program-query` returns all ten scoped edges: 7 calls,
2 reads, and 1 write. It returns 36 matching operation nodes and five related
endpoint nodes in the exploratory view. The query result is pinned at
[`query-result.jsonl`](query-result.jsonl).

The exact-only direct-call path query also returns
`00a45520 → 00a40550 → 00886930` in two hops. It uses direct-call graph edges
only; it does not prove CFG-feasible or runtime execution. Its artifact is
[`call-path-query.jsonl`](call-path-query.jsonl).

| Artifact | SHA-256 |
| --- | --- |
| Function Effect IR | `39149a87c687e12872b120ef5fafd72bc2e1862feea3d980c6e2f5594243ed22` |
| Semantic Program Graph | `7662c65c2db67e34f25ae92f0d7c5ec5c71e254c5b2549c5209f6974d4856c4e` |
| Evaluation result | `551a88c090493869fff577d2d225154adc4ff516e0e7340cb6fea69cbaeffb7b` |
| Query result | `5a4e07542f547c4dc0801239c1eefe4679e5b66b99fd6425ea56fed9b93b6777` |
| Direct-call path query | `17e645b00a2719d17967b4ed5cca53ab87f605ff98b7e03b3f21efc53b687302` |
| Consumer gold subgraph | `df606c38bf980329081929d63f2f1835f8e293eb78f6bdadd344ef140888496f` |

The retained [Function Effect IR](nfs-m23-graph-effects.jsonl),
[Semantic Program Graph](nfs-m23-semantic-graph.jsonl), and
[evaluation result](nfs-m23-semantic-graph-evaluation.json) preserve the
replay outputs. The consumer-owned gold remains in the NFS repository.
