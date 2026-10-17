# P-code to C function lowering

`revenginstr-pcode-c-function` emits native C for one raw-P-code function when
the function uses supported scalar operations and represented control flow. It
requires the corpus manifest and matching Ghidra language address-space table:

```bash
revenginstr-pcode-c-function functions.jsonl.gz \
  functions.jsonl.gz.manifest.json language-address-spaces.json 0x00401000 \
  --output function.c
```

Run `revenginstr-pcode-c-lowering-coverage` over the same three inputs to get a
hash-pinned count of fully lowerable functions and rejection reasons.

`revenginstr-pcode-c-lowering-corpus` streams lowerable functions into bounded
C shards and compiles each shard to an object file. Give it a clean output
directory and the target compiler; repeat `--compiler-arg` for target flags:

```bash
revenginstr-pcode-c-lowering-corpus functions.jsonl.gz \
  functions.jsonl.gz.manifest.json language-address-spaces.json build/ \
  --compiler i686-w64-mingw32-gcc --shard-size 500 --jobs 4 \
  --compiler-arg=-march=i686
```

The `build-report.json` records input hashes, the compiler and flags, rejection
counts, and each generated source/object hash. These objects contain generic
host callbacks; the consumer still needs a target-specific runtime, call/userop
dispatch, startup code, and a link map. Interrupted runs preserve a
`.build-state.json`; rerun the same command with `--resume` to verify the input,
compiler, builder, and lowerer hashes, then compile only missing object files.

The output function receives an `RviPcodeContext`. Its callbacks read and write
register and memory spaces as byte sequences. `LOAD`/`STORE` use the exact
language address-space ID, pointer size, addressable unit size, and endianness
from the table. Function-local P-code unique space is kept in a bounded local
byte array. `CALLOTHER` keeps the same callback signature: arguments up to 8
bytes occupy one `uint64_t`; raw 10- and 16-byte arguments occupy consecutive
least-significant-word-first `uint64_t` slots, while `sizes` retains one byte
width per logical argument. For a wide result, the callback writes
`ceil(output_size / 8)` words using the same ordering. The word ordering is
independent of target endianness. This keeps existing scalar callbacks and the
context layout unchanged.

The current subset covers scalar varnodes up to 8 bytes; raw 10-byte and
16-byte copy, memory, bitwise, extension, shift, and extraction operations;
binary80 conversions and arithmetic on x86 hosts with a 64-bit-significand
`long double`, integer and boolean operations listed in
`src/revenginstr/pcode/c_lowering.py`, integer division and remainder, 4-byte
and 8-byte floating arithmetic/conversions, `LOAD`,
`STORE`, direct conditional and unconditional branches within the function,
same-instruction conditional repeat branches, P-code-relative branches within
one instruction, computed jumps, direct
and indirect calls through the host `RviPcodeContext.call` callback, tail calls,
raw `RETURN`, x86 `WAIT` instructions with no P-code, and `CALLOTHER` through
the host `RviPcodeContext.userop` callback, keyed by Ghidra's language userop
index. Function-local P-code unique
space is compacted while preserving overlapping byte ranges. Computed jumps
dispatch to Ghidra's in-function flow targets, or to any instruction start in
the function when Ghidra supplies no target list; an outside target fails at
runtime. Binary80 helpers use the calling thread's current x87 control state;
the consumer must keep it aligned with the guest state for matching rounding.
On non-x86 hosts or hosts without binary80 `long double`, those operations
return an error. The 16-byte path treats values as opaque bytes except for the
listed bitwise and byte-oriented operations; it does not imply packed SIMD
arithmetic semantics. Relative branch targets outside the current
instruction's P-code fail closed. An x86 `WAIT` is emitted as a host `FWAIT`;
other non-NOP instructions without P-code remain rejected.
Generated Linux programs that use floating math must link with `-lm`. This
backend is an executable lowering milestone, not full NFS Shift recompilation
or a claim of behavioral parity.
