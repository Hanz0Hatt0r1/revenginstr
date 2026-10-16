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

Run it with:

```sh
GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_caller_argument_subtree.sh \
  <project-dir> <project-name> <program-name> <plan.tsv> <output.tsv>
```
