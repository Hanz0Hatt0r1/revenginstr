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
```

| Artifact | SHA-256 |
| --- | --- |
| Ghidra function P-code TSV | `d5605b3b688f269deffc276a76e6132f5562cfa7d4f26c54d4df0fc85600a564` |
| Ghidra receiver TSV | `0c88934d362437923524e7c4abaf308810d7fdb92a8065a3c267b9ca2997d9be` |
| Function Effect IR/2 | `3b10aaaf142e50db3d05a4cc1a0ec56dc2233f9b227fbc2ad7b660225f2e9e7a` |
| Semantic Program Graph/2 | `b625d3a6ff58e19c92a78bbd0de8eb38eb25e0a06ab8f9befc281b061a980856` |
