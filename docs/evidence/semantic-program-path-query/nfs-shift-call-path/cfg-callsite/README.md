# NFS SHIFT call-site CFG replay

This replay adds the captured Ghidra `FunctionPcodeCFG/3` row for
`00a45520` to the NFS SHIFT semantic graph slice in the parent directory. The
CFG row is copied byte-for-byte from the consumer-owned
`revenginstr_m23_direct_call_replay/00a45520` evidence. Its source replay
records the retail input identity, read-only Ghidra export, and pinned
RevEngInstr revision; this repository includes only the CFG record, not the
executable or Ghidra project.

The graph path `00a45520 → 00a40550` uses the exact call at `00a4556d`, P-code
time `102`. CFG/3 places that operation in block `3`; the exported successor
graph contains the entry-to-call-block witness `[0, 1, 2, 3]`. This proves
block-graph reachability of the call site from the function entry. It does not
prove that branch predicates permit the route or that the program executes it.

Rebuild the result from the repository root:

```sh
uv run --project . revenginstr-semantic-program-path-query \
  docs/evidence/semantic-program-path-query/nfs-shift-call-path/semantic-program-graph.jsonl \
  --source-function-entry 00a45520 \
  --target-function-entry 00a40550 \
  --view exact-only \
  --function-pcode-cfg docs/evidence/semantic-program-path-query/nfs-shift-call-path/cfg-callsite/function-pcode-cfg-v3.jsonl \
  --output docs/evidence/semantic-program-path-query/nfs-shift-call-path/cfg-callsite/direct-call-path-query.jsonl
```

| Artifact | SHA-256 |
| --- | --- |
| Ghidra Function P-code CFG/3 | `51c4fa8a6a2fac3def254ff1415962374b5aafce9dd569e7fce16ee69837ef62` |
| Semantic Program Path Query Result/1 | `a7696971eb9207469201c1d6d5c7f9b6972259829099f1cb3df16ab8d0cc4fc2` |
