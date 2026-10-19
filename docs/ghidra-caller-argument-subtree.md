# Bounded caller argument subtree export

`ghidra/ExportGhidraCallerArgumentSubtree.java` exports bounded backward SSA trees
for actual arguments at direct call sites. Plan `/1` has three columns:
`plan_id`, `callee_entry`, and `parameter_index`. Plan `/2` adds `caller_entry`;
put `-` there to discover direct callers or an address to scope that row to one
caller. `plan_id` is opaque consumer metadata. The output is metadata-only TSV
and follows `schemas/ghidra-caller-argument-subtree-v1.schema.json`. Plan row
contracts are `schemas/ghidra-caller-argument-subtree-plan-v1.schema.json` and
`schemas/ghidra-caller-argument-subtree-plan-v2.schema.json`.

The exporter caps each tree at 12 levels and 96 nodes, and each callee at 128
direct caller functions. A summary row uses `caller_limit_reached` when another
distinct caller exists beyond that cap. Use `--caller-entry <address>` to
restrict a plan to one caller function and avoid scanning the other callers. The
selected caller is decompiled directly, so the filter also handles recursive
self-calls and callsites missing from Ghidra's reference index; the exporter
still verifies the direct P-code target before emitting argument rows. Without
the filter, caller discovery uses call references and includes self-recursion.
For a mixed closure export, use plan `/2` and set `caller_entry` on each row;
this avoids the global caller cap without starting one Ghidra process per
caller. Do not combine caller-scoped rows with `--caller-entry`.
Summary rows report direct callers, decompile failures, and matched calls.
Consumers compare those counts with their own expected coverage and keep any
project-specific fields in their local adapter.
Call argument rows depend on Ghidra's recovered function signatures. The
read-only exporter consumes signatures already saved in the project. Apply
Parameter ID first to the functions in the bounded call closure, using a
writable project copy when the original analysis must be preserved:

```bash
cp -a /path/to/projects/project-name /path/to/projects/project-name-paramid
GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_parameter_id.sh \
  /path/to/projects/project-name-paramid project-name program-name \
  00401000 00402000 00403000
```

The runner updates the selected function signatures in the Ghidra database;
subsequent export wrappers remain read-only. Pass callees before callers so
recovered prototypes are available during caller analysis. For recursive call
closures, run the full list twice. Include callers and callees whose P-code
argument lists participate in the evidence path. The subtree exporter reports
unmatched caller functions in its summary. For recursive closures, repeat the
full list until a pass makes no further signature changes.

An optional `--parameter-root-output <roots.tsv>` sidecar records a call
argument only when its root varnode matches a formal parameter of the caller
function and has no defining P-code operation. A derived SSA value is not a
direct root merely because Ghidra assigned it the same `HighVariable` as a
formal. It follows `REVENGINSTR.GhidraCallerArgumentParameterRoot/1` and keeps
the plan id, callee formal, caller/call-site, and caller formal indices.

For prototype inference, request the program-pinned v3 form:

```sh
GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_caller_argument_subtree.sh \
  <project-dir> <project-name> <program-name> <plan.tsv> <output.tsv> \
  --prototype-parameter-root-output <prototype-roots.tsv>
```

`GhidraCallerArgumentParameterRoot/3` carries the Ghidra program id and
executable SHA-256 in every row. `revenginstr-prototype-infer` requires those
values to match its decompiler and call observations before using a root to
propagate a formal parameter shape. This sidecar records exact untransformed
formal arguments only; the v1/v2 memory-analysis sidecars retain their existing
contracts.

An optional `--parameter-offset-root-output <offset-roots.tsv>` sidecar also
records exact constant pointer offsets from a caller formal. Its
`REVENGINSTR.GhidraCallerArgumentParameterRoot/2` rows include a signed byte
offset; only same-width COPY/CAST and constant INT_ADD, INT_SUB, PTRSUB, or
PTRADD chains are accepted. A `MULTIEQUAL` is accepted only when every incoming
value resolves to the same formal and byte offset; cycles, unresolved branches,
and loop-carried values with changing offsets are omitted. Side-effect-dependent
`INDIRECT` values and other expressions are also omitted. The interprocedural
memory consumer accepts both versions and shifts callee store offsets before
proving byte ranges disjoint. It tracks at most 64 exact offsets per formal;
overflow remains may-alias. The default invocation and subtree output remain
unchanged.
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
