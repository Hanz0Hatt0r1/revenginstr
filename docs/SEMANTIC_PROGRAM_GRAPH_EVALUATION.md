# Semantic program graph evaluation

Consumers keep adjudicated subgraphs in their own repositories. A
[`SemanticProgramGraphGold/1`](../schemas/semantic-program-graph-gold-v1.schema.json)
JSONL row pins one graph and declares a node scope plus the relations that are
complete in that scope. Each expected edge cites the source records used to
adjudicate it; the evaluator rejects references to the graph being scored and
rejects edge endpoint kinds that do not match the relation.
The `record_index` meaning is defined by `source_format` (for example, a
one-based TSV data row or a Markdown line); consumer evidence documentation
must state that indexing convention. Gold edge endpoint kinds must be valid
for their relation and graph version. When a gold edge's source operation is
present in the evaluated graph, the evaluator also checks the expected opcode
(`CALL`, `LOAD`, `STORE`, or `CALLIND`); absent source nodes remain eligible to
score as recall misses. Reviewers must assess source records independently of
the graph projection.
Unknown or incomplete relations are excluded from recall and edge precision.
For `has_field`, the gold contract accepts both `type → layout_field` edges
from reviewed layout hypotheses and `type → field` edges from exact member-map
joins in SemanticProgramGraph/3 or /4. If a member map was also used to build
the graph, it is construction evidence and cannot serve as an independent
accuracy label for that same join; use separate adjudication evidence for an
evaluation claim.

Run the hash-pinned evaluator with:

```sh
revenginstr-semantic-program-graph-evaluate semantic-program-graph.jsonl \
  gold-subgraphs.jsonl \
  --view exact-only \
  --output graph-evaluation.json
```

The result is
[`SemanticProgramGraphEvaluation/1`](../schemas/semantic-program-graph-evaluation-v1.schema.json).
Per-relation candidate precision and recall are emitted only for
declared-complete relations.
`unsupported_edge_rate` is the share of selected candidate edges absent from
the adjudicated gold set within that scope. `accepted_edge_precision` scores
uncontested exact-static edges and other uncontested edges meeting the
confidence threshold within complete relations; it is `null` when no labeled
edge passes either rule.
`provenance_completeness` checks that selected edges carry a nonempty support
chain with source format, artifact hash, and record index. It does not check
that every referenced source artifact is available on disk.

This evaluates the supplied scopes only. It does not treat unreviewed graph
edges as negatives, and a report with no accepted edges does not establish an
accepted-edge precision gate.
