# Bounded caller argument subtree export

`ghidra/ExportGhidraCallerArgumentSubtree.java` exports bounded backward SSA trees
for actual arguments at direct call sites. Its input TSV has exactly three
columns: `plan_id`, `callee_entry`, and `parameter_index`. `plan_id` is an
opaque stable key supplied by the caller. The output is metadata-only TSV and
follows `schemas/ghidra-caller-argument-subtree-v1.schema.json`.
The plan row contract is `schemas/ghidra-caller-argument-subtree-plan-v1.schema.json`.

The exporter caps each tree at 12 levels and 96 nodes, and each callee at 128
direct caller functions. A summary row uses `caller_limit_reached` when another
distinct caller exists beyond that cap. Use `--caller-entry <address>` to
restrict a plan to one caller function and avoid scanning the other callers.
Summary rows report direct callers, decompile failures, and matched calls.
Consumers compare those counts with their own expected coverage and keep any
project-specific fields in their local adapter.
Call argument rows depend on Ghidra's recovered function signatures. If the
`Decompiler Parameter ID` analyzer has not run, a caller's P-code may omit
argument operands; run that analyzer before exporting. The wrapper remains
read-only and reports unmatched caller functions in the summary.

An optional `--parameter-root-output <roots.tsv>` sidecar records a call
argument only when its root varnode matches a formal parameter of the caller
function. It follows `REVENGINSTR.GhidraCallerArgumentParameterRoot/1` and keeps
the plan id, callee formal, caller/call-site, and caller formal indices.

An optional `--parameter-offset-root-output <offset-roots.tsv>` sidecar also
records exact constant pointer offsets from a caller formal. Its
`REVENGINSTR.GhidraCallerArgumentParameterRoot/2` rows include a signed byte
offset; only same-width COPY/CAST and constant INT_ADD, INT_SUB, PTRSUB, or
PTRADD chains are accepted. Side-effect-dependent `INDIRECT` values and other
expressions are omitted. The interprocedural memory consumer accepts both
versions and shifts callee store offsets before proving byte ranges disjoint.
It tracks at most 64 exact offsets per formal; overflow remains may-alias. The
default invocation and subtree output remain unchanged.
The synthetic caller-argument and formal-root TSVs in
`tests/fixtures/caller-argument/` exercise a two-edge recursive propagation
path and are validated against both exporter row schemas.

Run it with:

```sh
GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_caller_argument_subtree.sh \
  <project-dir> <project-name> <program-name> <plan.tsv> <output.tsv>
```

To request both artifacts:

```sh
GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_caller_argument_subtree.sh \
  <project-dir> <project-name> <program-name> <plan.tsv> <output.tsv> \
  --parameter-root-output <roots.tsv>
```

To include constant-offset formal roots:

```sh
GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_caller_argument_subtree.sh \
  <project-dir> <project-name> <program-name> <plan.tsv> <output.tsv> \
  --parameter-offset-root-output <offset-roots.tsv>
```

To restrict the plan to one caller function:

```sh
GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_caller_argument_subtree.sh \
  <project-dir> <project-name> <program-name> <plan.tsv> <output.tsv> \
  --parameter-offset-root-output <offset-roots.tsv> --caller-entry 00402000
```
