# Program-pinned indirect-call replay

`callind.elf` is built from `callind.c` with GCC 16.2.1 using:

```sh
cc -O0 -fno-pie -no-pie -nostdlib \
  -Wl,-e,call_callback -Wl,--build-id=none \
  -o callind.elf callind.c
```

Ghidra 12.1.2 (Java 21) imported the ELF, then the read-only batch exporter
captured both functions into `flow.tsv`, `callind.jsonl`, and
`acquisition.jsonl`. The standalone indirect-call runner was run separately on
`call_callback`; its JSONL output was byte-identical to the batch export.
`pointer-provenance.jsonl` and `pointer-slots.jsonl` record the downstream
join: the target expression is a `CAST`, so the slot analyzer reports
`unsupported_target_operation` instead of inventing a memory slot.

The single `GhidraIndirectCallEvidence/2` row hashes the exact ELF and records
its x86-64 ABI. It joins to the exact `CALLIND` row and argument count in
`flow.tsv`. Its target expression remains a bounded Ghidra expression; it does
not claim that the loaded function pointer has been resolved to `plus_one`.
