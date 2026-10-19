# NFS SHIFT graph projection audit

This reviewer-curated subgraph checks the seven direct-call rows in the
captured P-code for functions `00a45520` and `00a40550`. Expected targets are
`00a40550`, `008cb4f0`, `00901960`, and `00886930`. Gold edges cite the original
[`FunctionPcodeFlow/1` capture](../../semantic-program-path-query/nfs-shift-call-path/function-pcode-flow.tsv),
not the graph or evaluation output. The audit scope declares only `calls`
complete.

Rebuild the report from the repository root:

```sh
uv run --project . revenginstr-semantic-program-graph-evaluate \
  docs/evidence/semantic-program-path-query/nfs-shift-call-path/semantic-program-graph.jsonl \
  docs/evidence/semantic-program-graph-evaluation/nfs-shift-call-path/gold-subgraphs.jsonl \
  --view exact-only \
  --output docs/evidence/semantic-program-graph-evaluation/nfs-shift-call-path/evaluation.json
```

| Artifact | SHA-256 |
| --- | --- |
| Gold subgraph | `d11991b337369e4d5db25691550cacdd685eaf15d58f3a5b13d1be2c9380ef7e` |
| Semantic Program Graph Evaluation/1 | `87cf9340dc85951524b33afc01a3173bf58e27653530480b3265aa5079c24fa3` |

Result: 7/7 candidate calls match the reviewed source rows, and each edge has
the provenance fields required by the graph schema. All seven uncontested
exact-static calls are accepted; accepted-edge precision is 1.0.
