# Exact function replay: `006642a5`

The input is the pinned retail `SHIFT.exe`, SHA-256
`eca479aa2d8dbb88bc55709d91ae5c7159ae1b00fc9555d6701000c26de8aee1`. The
capture used Ghidra 12.1.2 development build and Java 21.0.12.1. To avoid
changing the saved project, the function was seeded in a disposable copy of
the project; the subsequent CFG export opened that copy read-only, with
analysis disabled.

`006642a5` was absent from the pinned function inventory and is the tail-jump
target of thunk `006642a0`. Seeding confirmed an instruction at the requested
entry, rejected entries inside another function, and created an exact 43-byte
function. The P-code export contains 18 operations; CFG/5 contains all 18
operations in three blocks with one entry block and no skipped functions. It
contains two direct `CALL`s and no `CALLIND`. The CFG's two `INDIRECT` ops are
source-linked to those direct calls.

The body tests and updates global guard `00bfc818`. On the initialization
path it calls constructor `00664140` for global `00bfc728`, registers callback
`00a9e620` through `_atexit` (`00900fb3`), and returns the global pointer.
The CFG records the guard's branch to the common return block. This capture
establishes static function and control-flow facts; it does not establish
which runtime path is taken.

Reproduce from the repository root using a disposable copy containing only
the Ghidra project descriptor and repository:

```sh
SOURCE_PROJECT=/path/to/ghidra-projects/shift
PROJECT_COPY=$(mktemp -d /tmp/revenginstr-shift-006642a5.XXXXXX)
cp "$SOURCE_PROJECT/shift.gpr" "$PROJECT_COPY/"
cp -a "$SOURCE_PROJECT/shift.rep" "$PROJECT_COPY/"

GHIDRA_HOME=/opt/ghidra JAVA_HOME=/usr/lib/jvm/java-21-openjdk \
  PATH=/usr/lib/jvm/java-21-openjdk/bin:$PATH \
  scripts/run_ghidra_seeded_function_pcode_flow.sh \
  "$PROJECT_COPY" shift SHIFT.exe 006642a5 \
  /tmp/field20-006642a5-pcode-flow.tsv --writable-project-copy

GHIDRA_HOME=/opt/ghidra JAVA_HOME=/usr/lib/jvm/java-21-openjdk \
  PATH=/usr/lib/jvm/java-21-openjdk/bin:$PATH \
  scripts/run_ghidra_function_pcode_cfg.sh \
  "$PROJECT_COPY" shift SHIFT.exe \
  /tmp/field20-006642a5-pcode-cfg-v5.jsonl \
  nfs-shift:SHIFT.exe 006642a5 --entry-block-indices
```

Selected terminal markers from the successful runs (not complete Ghidra logs):

```text
GHIDRA_SEEDED_FUNCTION_ENTRY=006642a5
GHIDRA_SEEDED_FUNCTION_BODY_BYTES=43
GHIDRA_FUNCTION_PCODE_FLOW_FORMAT=REVENGINSTR.GhidraFunctionPcodeFlow/1
GHIDRA_FUNCTION_PCODE_FLOW_FUNCTION=006642a5
GHIDRA_FUNCTION_PCODE_FLOW_ROWS=18
GHIDRA_FUNCTION_PCODE_CFG_FORMAT=REVENGINSTR.GhidraFunctionPcodeCFG/5
GHIDRA_FUNCTION_PCODE_CFG_FUNCTIONS=1
GHIDRA_FUNCTION_PCODE_CFG_EXPORTED_FUNCTIONS=1
GHIDRA_FUNCTION_PCODE_CFG_SKIPPED_FUNCTIONS=0
```

The retained outputs are [`field20-006642a5-pcode-flow.tsv`](field20-006642a5-pcode-flow.tsv)
and [`field20-006642a5-pcode-cfg-v5.jsonl`](field20-006642a5-pcode-cfg-v5.jsonl).
The function inventory, acquisition record, and empty `CALLIND` set are
[`field20-006642a5-functions.txt`](field20-006642a5-functions.txt),
[`field20-006642a5-acquisition.jsonl`](field20-006642a5-acquisition.jsonl),
and [`field20-006642a5-callind.jsonl`](field20-006642a5-callind.jsonl).
