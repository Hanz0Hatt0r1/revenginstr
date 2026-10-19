# Ghidra tail-call return-shape replay

This fixture records a real Ghidra 12.1.2 analysis of a small 32-bit x86
object compiled from `return-flow.c` with GCC 16.2.1. The object SHA-256 is
`6f5af8a317f710d2ad4154bacf78d1836bf0e453ef8be3834c73dd3d7aa364a1`.
Ghidra recovers `source` as returning `int *`, but models `forward` as `void`.
Its High-P-code has exactly a `CALL source` followed by `RETURN`; it does not
preserve a call output. The binary cannot prove whether `forward` returns the
call result or ignores it, so inference retains Ghidra's primary candidate and
adds only a confidence-0.2 `possible-tail-call-return` alternative.

Recreate the captured artifacts from the repository root:

```sh
REPLAY=/tmp/revenginstr-tail-return
mkdir -p "$REPLAY/projects"
gcc -m32 -O0 -g0 -fno-pic -fno-omit-frame-pointer -fno-stack-protector \
  -fno-asynchronous-unwind-tables -c \
  tests/fixtures/ghidra-tail-call-return/return-flow.c \
  -o "$REPLAY/return-flow.o"
sha256sum "$REPLAY/return-flow.o"
GHIDRA_HOME=/opt/ghidra JAVA_HOME=/usr/lib/jvm/java-21-openjdk \
PATH=/usr/lib/jvm/java-21-openjdk/bin:/usr/bin:/bin \
  /opt/ghidra/support/analyzeHeadless "$REPLAY/projects" Prototype \
  -import "$REPLAY/return-flow.o" -overwrite
GHIDRA_HOME=/opt/ghidra JAVA_HOME=/usr/lib/jvm/java-21-openjdk \
PATH=/usr/lib/jvm/java-21-openjdk/bin:/usr/bin:/bin \
  scripts/run_ghidra_decompiler_parameters.sh "$REPLAY/projects" Prototype \
  return-flow.o tests/fixtures/ghidra-tail-call-return/plan.tsv \
  "$REPLAY/decompiler-parameters.jsonl"
GHIDRA_HOME=/opt/ghidra JAVA_HOME=/usr/lib/jvm/java-21-openjdk \
PATH=/usr/lib/jvm/java-21-openjdk/bin:/usr/bin:/bin \
  scripts/run_ghidra_function_pcode_flow.sh "$REPLAY/projects" Prototype \
  return-flow.o 00010017 "$REPLAY/forward-flow.tsv"
revenginstr-direct-call-arguments "$REPLAY/forward-flow.tsv" \
  --program-id return-flow.o \
  --program-sha256 6f5af8a317f710d2ad4154bacf78d1836bf0e453ef8be3834c73dd3d7aa364a1 \
  --output "$REPLAY/call-observations.jsonl"
revenginstr-prototype-infer "$REPLAY/decompiler-parameters.jsonl" \
  "$REPLAY/call-observations.jsonl" \
  --function-pcode-flow "$REPLAY/forward-flow.tsv" \
  --output "$REPLAY/hypotheses.jsonl"
```

The checked-in `decompiler-parameters.jsonl`, `forward-flow.tsv`,
`call-observations.jsonl`, and `hypotheses.jsonl` are the captured outputs.
The source is included for reproducibility; the object and Ghidra project are
not.
