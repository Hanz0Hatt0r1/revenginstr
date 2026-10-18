# SemanticProgramPathQueryResult/1 NFS SHIFT replay

This replay starts from captured NFS SHIFT Ghidra P-code rows for functions
`00a40550` and `00a45520`, plus parameter-rooted store/load exports. It builds
the Effect IR and Semantic Program Graph, then queries for a direct-call path
from `00a45520` to `00886930`.

The graph contains 44 nodes and 52 edges. The exact, uncontested call graph
contains this two-step route:

```text
00a45520 --CALL 00a4556d--> 00a40550 --CALL 00a405bf--> 00886930
```

Each path step in the result embeds caller/callee function context, the source
operation, the function-to-call `contains` edge, and the exact `calls` edge
with their original support. The query finds one simple path within 12 hops;
this evidence does not establish CFG-feasible execution. No uncertain call
sites appear in the source function's direct-call reachable region in this
captured slice.

Rebuild the outputs from the committed inputs from the repository root:

```sh
uv run --project . revenginstr-effect-ir \
  --program-id 'nfs-shift:SHIFT.exe' \
  --parameter-stores docs/evidence/semantic-program-path-query/nfs-shift-call-path/parameter-stores.tsv \
  --parameter-loads docs/evidence/semantic-program-path-query/nfs-shift-call-path/parameter-loads.tsv \
  --pcode-flow docs/evidence/semantic-program-path-query/nfs-shift-call-path/function-pcode-flow.tsv \
  --include-generic-memory-ops \
  --output docs/evidence/semantic-program-path-query/nfs-shift-call-path/function-effect-ir.jsonl

uv run --project . revenginstr-semantic-program-graph \
  docs/evidence/semantic-program-path-query/nfs-shift-call-path/function-effect-ir.jsonl \
  --output docs/evidence/semantic-program-path-query/nfs-shift-call-path/semantic-program-graph.jsonl

uv run --project . revenginstr-semantic-program-path-query \
  docs/evidence/semantic-program-path-query/nfs-shift-call-path/semantic-program-graph.jsonl \
  --source-function-entry 00a45520 \
  --target-function-entry 00886930 \
  --view exact-only \
  --max-hops 12 \
  --output docs/evidence/semantic-program-path-query/nfs-shift-call-path/direct-call-path-query.jsonl
```

| Artifact | SHA-256 |
| --- | --- |
| Ghidra function P-code flow/1 | `0f7601c2436881c411367c7a69b28bf5d548721c8b7a8a5a31ece1e6f5cdd4c4` |
| Ghidra parameter store field/1 | `d00a780fa47582ce946a10bdab86cbce2971314a5ccc7db80c959f6de3970b36` |
| Ghidra parameter load field/1 | `facc794c48e31ea72ee031a25dc1f6bb80a68392efa91c9c4ecf740a1afb2972` |
| Function Effect IR/2 | `0ff2509aaaf35b8a48274d5970dab9782aad2d2cf3c723379714abb5e239daab` |
| Semantic Program Graph/1 | `3406b35c851696ed180227cf27dbcfa2e40bf1f2c4cde22d253c114e69713bbb` |
| Semantic Program Path Query Result/1 | `0fe328de16cd7a63def9c6683e11c46b1ddcfba3bb4064836fcabe58f803c7e0` |
