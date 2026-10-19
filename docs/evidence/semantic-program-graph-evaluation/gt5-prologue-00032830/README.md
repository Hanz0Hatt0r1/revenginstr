# GT5 Prologue graph projection audit

This reviewer-curated subgraph checks the two direct calls in the captured
P-code rows for function `00032830`. The expected relations point to functions
`000322a8` and `000326e0`. Gold edges cite the original
[`FunctionPcodeFlow/1` capture](../../semantic-program-graph-v2/gt5-prologue-00032830/function-pcode-flow.tsv),
not the graph or evaluation output. The audit scope declares only `calls`
complete.

Rebuild the report from the repository root:

```sh
uv run --project . revenginstr-semantic-program-graph-evaluate \
  docs/evidence/semantic-program-graph-v2/gt5-prologue-00032830/semantic-program-graph.jsonl \
  docs/evidence/semantic-program-graph-evaluation/gt5-prologue-00032830/gold-subgraphs.jsonl \
  --view exact-only \
  --output docs/evidence/semantic-program-graph-evaluation/gt5-prologue-00032830/evaluation.json
```

| Artifact | SHA-256 |
| --- | --- |
| Gold subgraph | `493952c058d50ab3bb70ca85ac91433374ad6dfa9c77ef5ec18becf611457bfc` |
| Semantic Program Graph Evaluation/1 | `67677a350b92ea67b591a3e5b629f4d222f20dcd216844410bd302515d09062f` |

Result: 2/2 candidate calls match the reviewed source rows, and each edge has
the provenance fields required by the graph schema. Both uncontested
exact-static calls are accepted; accepted-edge precision is 1.0.
