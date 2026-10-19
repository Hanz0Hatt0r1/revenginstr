# Stripped prototype replay

This is a small x86-32 ELF object compiled without debug information. It is
812 bytes and has SHA-256
`237d1e481b3b2c5e6bfe64c310a1486b451d3d2cf27281649a6338cfee664025`.
`readelf -S` reports no `.debug*` sections. Rebuild it with GCC 16.2.1 using:

```sh
gcc -m32 -O0 -g0 -fno-pic -fno-omit-frame-pointer -fno-stack-protector \
  -fno-asynchronous-unwind-tables -c untyped.c -o untyped.o
```

The exports were captured from Ghidra 12.1.2 with Java 21 after normal x86
analysis. Both functions have Ghidra signature source `DEFAULT` and no locked
formal types. Ghidra identifies `mystery_mutate` parameter 0 and its return as
pointers, while `mystery_caller` parameter 0 remains `undefined4`. The exact
caller-argument root proves that this formal reaches `mystery_mutate` parameter
0 unchanged. `revenginstr-prototype-infer` consequently proposes a pointer for
`mystery_caller` and keeps the result in review state.

`coverage.json` reports full evidence capture for the two-function Ghidra
index. That is a capture-coverage result, not independent prototype gold.

`gold.jsonl` is source-adjudicated against the C function definitions at lines
5 and 10 and the matching Ghidra function-index rows. `evaluation.json` records
the current result at the default 0.95 acceptance threshold: no candidate
reaches that threshold, parameter counts and parameter shapes are both 2/2
correct, and return shapes are 1/2 correct because `mystery_caller` still has
an unknown return type. This fixture measures the inference boundary; it does
not imply that the project is ready for broad automatic prototype recovery.
