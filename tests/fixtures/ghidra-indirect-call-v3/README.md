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
The v3 exporter follows the `CAST` target to the exact static address
`0x00403000`, reads one little-endian pointer-width value from the imported
program memory, and resolves it to the exact Ghidra function entry
`0x00401000` (`plus_one`). The standalone exporter was run separately and its
JSONL output was byte-identical to the batch sidecar.

`pointer-provenance.jsonl` and `pointer-slots.jsonl` record the downstream
structural join. The pointer-slot analyzer still reports
`unsupported_target_operation` for the `CAST` shape; the separate exact target
resolution does not claim a vtable or runtime dispatch relationship.

The single `GhidraIndirectCallEvidence/3` row hashes the exact ELF and records
its x86-64 ABI. It joins to the exact `CALLIND` row and argument count in
`flow.tsv`; the resolved target can constrain arity in
`revenginstr-prototype-infer` when supplied alongside the matching decompiler
snapshot.
