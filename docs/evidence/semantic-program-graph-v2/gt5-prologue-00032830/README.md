# Semantic Program Graph/2 replay

This small evidence slice is exported from the saved GT5 Prologue `EBOOT.elf`
Ghidra project with Ghidra 12.1.2 DEV. The binary and Ghidra project are not
included. The captured generic exports make the Effect IR and graph stages
replayable from this repository.

The P-code export contains 50 rows for function `00032830`. Its indirect call
is at `00032880`, P-code time `66`. The receiver export contains the matching
row and records `receiver_present=1`, raw receiver type `uint *`, pointee type
`uint`, and transparent-flow pointee `uint`. Those are Ghidra type observations,
not a recovered class or dispatch target.

The replay produces 17 Function Effect IR/2 facts and one program graph with 22
nodes and 24 edges. Exactly one `observes_receiver` edge joins the receiver row
to the `CALLIND` at the matching function, address, and time. The indirect call
does not become a `calls` edge.

The indirect-call graph query returns that operation, its receiver observation
as endpoint context, and the one `observes_receiver` edge. The
`accepted-high-confidence` view returns no records because graph confidence is
null.

A path query from `00032830` to `000322a8` returns the exact direct call at
`0003289c` and reports the `CALLIND` at `00032880` as an uncertain call
frontier in the source function. The replay also joins a read-only Ghidra
CFG/3 export to the two call sites by function entry, address, P-code time, and
opcode. This CFG/3 capture was exported from the saved GT5 Ghidra 12.1.2 DEV
project in read-only, no-analysis mode using the documented
[`Ghidra function CFG exporter`](../../../GHIDRA_FUNCTION_PCODE_CFG.md).
The direct call at time `95` is in block `3`, reachable from entry via
`[0, 2, 3]`; the indirect call at time `66` is in block `1`, reachable via
`[0, 1]`. The path step retains both function nodes, the call operation, its
membership/call edges, and the CFG witness. The frontier retains the indirect
call's membership edge and empty call-graph reachability witness because it
is in the source function; CFG annotations show its entry-to-block route. It
does not assign that indirect call a target. Block-graph reachability does not
prove branch-predicate feasibility or runtime execution.

To regenerate the derived records from the captured exports, run from the
repository root:

```sh
revenginstr-effect-ir \
  --program-id EBOOT.elf \
  --pcode-flow docs/evidence/semantic-program-graph-v2/gt5-prologue-00032830/function-pcode-flow.tsv \
  --include-generic-memory-ops \
  --output docs/evidence/semantic-program-graph-v2/gt5-prologue-00032830/function-effect-ir.jsonl

revenginstr-semantic-program-graph \
  docs/evidence/semantic-program-graph-v2/gt5-prologue-00032830/function-effect-ir.jsonl \
  --receiver-types docs/evidence/semantic-program-graph-v2/gt5-prologue-00032830/indirect-receiver-types.tsv \
  --output docs/evidence/semantic-program-graph-v2/gt5-prologue-00032830/semantic-program-graph.jsonl

revenginstr-semantic-program-query \
  docs/evidence/semantic-program-graph-v2/gt5-prologue-00032830/semantic-program-graph.jsonl \
  --view exploratory --kind operation --call-target-state indirect \
  --relation observes_receiver \
  --output docs/evidence/semantic-program-graph-v2/gt5-prologue-00032830/indirect-call-query.jsonl

revenginstr-semantic-program-path-query \
  docs/evidence/semantic-program-graph-v2/gt5-prologue-00032830/semantic-program-graph.jsonl \
  --source-function-entry 00032830 --target-function-entry 000322a8 \
  --view exact-only \
  --function-pcode-cfg docs/evidence/semantic-program-graph-v2/gt5-prologue-00032830/function-pcode-cfg-v3.jsonl \
  --output docs/evidence/semantic-program-graph-v2/gt5-prologue-00032830/direct-call-path-query.jsonl
```

| Artifact | SHA-256 |
| --- | --- |
| Ghidra function P-code TSV | `d5605b3b688f269deffc276a76e6132f5562cfa7d4f26c54d4df0fc85600a564` |
| Ghidra receiver TSV | `0c88934d362437923524e7c4abaf308810d7fdb92a8065a3c267b9ca2997d9be` |
| Ghidra function P-code CFG/3 | `a1dc25540dca3eb72c797d3d2e195a309a292094a15f1f49fd92749afdc3e6ec` |
| Function Effect IR/2 | `3b10aaaf142e50db3d05a4cc1a0ec56dc2233f9b227fbc2ad7b660225f2e9e7a` |
| Semantic Program Graph/2 | `b625d3a6ff58e19c92a78bbd0de8eb38eb25e0a06ab8f9befc281b061a980856` |
| Semantic Program Query Result/1 | `03f39dc1333941c8f449036d645005530dfcdba61df383f01042dd0208d8a07c` |
| Semantic Program Path Query Result/1 | `335303907af6b4449aa012e4410f3ec91919fe44aa83e784f10e6e74f8e86c4c` |
