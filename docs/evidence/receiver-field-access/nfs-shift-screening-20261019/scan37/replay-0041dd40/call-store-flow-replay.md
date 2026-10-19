# Call-result-to-store replay

This replay applies `revenginstr-receiver-call-store-flow` to the retained
`field20-pcode-flow.tsv` export. The input is pinned by the parent evidence
manifest; its SHA-256 is
`e08449432fd3c7b32a964fc2e7f95d00ce8b5df459f488d538d56b77725ca8ab`.

The command emitted six schema-valid structural graphs. Five paths in
`0066eff0` reach the `STORE` at `0066f215` (P-code time 96) through
`CALL → CAST → MULTIEQUAL → CAST → STORE`. The five calls are at `0066f063`,
`0066f0d5`, `0066f13f`, `0066f1a1`, and `0066f208`. The separately reviewed
memory-store capture maps that exact store to the receiver object's `+0x20`
field.

The sixth path is the call at `00673180` reaching a different `STORE` at
`00673185`. No field identity is assigned to that sink by this replay.

The output is [`call-store-flow.jsonl`](call-store-flow.jsonl), SHA-256
`5da217124af539089390fa7d78a2c7f7c6fd5a70e9b51900daa243bd03d90fe4`.
It was schema-validated against
[`receiver-provenance-graph-v1.schema.json`](../../../../../../schemas/receiver-provenance-graph-v1.schema.json),
SHA-256
`a8e9475e64b2300d110f9324726fac8c743c771e2314848fd61826c309d1bf94`.

Reproduce from the repository root with:

```sh
revenginstr-receiver-call-store-flow \
  docs/evidence/receiver-field-access/nfs-shift-screening-20261019/scan37/replay-0041dd40/field20-pcode-flow.tsv \
  --program-id 'nfs-shift:SHIFT.exe' \
  --output /tmp/call-store-flow.jsonl --max-graphs 50000
```

The graph records def-use paths only. `MULTIEQUAL` alternatives are not
branch-resolved, and the replay does not identify returned object types,
runtime referents, or feasible execution paths.

## Wider closure replay

The same command was applied to the retained `closure-pcode-flow.tsv` capture:
7,576 rows across 100 functions, SHA-256
`171beb5825a0c39c09d2fb2ee4ed0ef779f54b20223839746ebb06d24eaf764a`. It emitted
32 schema-valid graphs in eight functions. All 32 sources are direct `CALL`
operations; 11 paths go directly to `STORE`, while 21 include intermediate
P-code operations. The wider paths include `LOAD`, `PTRADD`, and `MULTIEQUAL`,
so they show structural dependence to a store's value operand, not unchanged
copying of the call result or a feasible runtime path.

The frozen output is [`call-store-flow-closure.jsonl`](call-store-flow-closure.jsonl),
SHA-256
`1166306fd1202db811e8a817912243ef5dff8cf8496b1082cabe9b97e0ee5af7`. Reproduce
it with:

```sh
revenginstr-receiver-call-store-flow \
  docs/evidence/receiver-field-access/nfs-shift-screening-20261019/scan37/replay-0041dd40/closure-pcode-flow.tsv \
  --program-id 'nfs-shift:SHIFT.exe' \
  --output /tmp/call-store-flow-closure.jsonl --max-graphs 50000
```
