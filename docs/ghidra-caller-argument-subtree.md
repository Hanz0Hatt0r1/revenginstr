# Bounded caller argument subtree export

`ghidra/ExportGhidraCallerArgumentSubtree.java` exports bounded backward SSA trees
for actual arguments at direct call sites. Its input TSV has exactly three
columns: `plan_id`, `callee_entry`, and `parameter_index`. `plan_id` is an
opaque stable key supplied by the caller. The output is metadata-only TSV and
follows `schemas/ghidra-caller-argument-subtree-v1.schema.json`.
The plan row contract is `schemas/ghidra-caller-argument-subtree-plan-v1.schema.json`.

The exporter caps each tree at 12 levels and 96 nodes, and each callee at 128
direct caller functions. Summary rows report direct callers, decompile
failures, and matched calls. Consumers compare those counts with their own
expected coverage and keep any project-specific fields in their local adapter.

An optional `--parameter-root-output <roots.tsv>` sidecar records a call
argument only when its root varnode matches a formal parameter of the caller
function. It follows `REVENGINSTR.GhidraCallerArgumentParameterRoot/1` and keeps
the plan id, callee formal, caller/call-site, and caller formal indices. The
default invocation and subtree output remain unchanged. Non-parameter roots,
including expressions derived from a parameter, are omitted so recursive
propagation can start only from explicit value identity.

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
