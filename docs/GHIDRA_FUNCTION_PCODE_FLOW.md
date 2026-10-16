# Ghidra function High P-code flow

`ExportFunctionPcodeFlow.java` exports the High P-code operations for one
function from an existing Ghidra analysis database. It includes operation
sequence addresses, stable varnode dependency tokens, and resolved direct-call
targets. It does not export instruction bytes, assembly, decompiler C text,
strings, or source assets.

The `REVENGINSTR.GhidraFunctionPcodeFlow/1` TSV row schema is defined in
`schemas/ghidra-function-pcode-flow-v1.schema.json`. The legacy-compatible TSV
header is:

```text
function_entry  op_address  op_time  opcode  output  inputs  callee_entry  callee_name
```

Tabs separate columns. All values are strings except `op_time`, a decimal
sequence number. Address and symbol cells reflect the selected input program;
the exporter logic and row contract are project-neutral. Existing consumers can
continue reading the metadata-only TSV without adding a format column.
The synthetic row in `tests/fixtures/ghidra-function-pcode-flow.tsv` is shared by
the single-function and bounded exporters and is validated against the row
schema.

Run the exporter against an already analyzed project:

```bash
GHIDRA_HOME=/opt/ghidra \
  scripts/run_ghidra_function_pcode_flow.sh \
  /path/to/projects project-name program-name 00401000 /tmp/function-flow.tsv
```

The runner uses `-readOnly -noanalysis` and a temporary script directory, so it
does not alter the project analysis or compile unrelated scripts. Consumers
should retain their existing exporter copy as a fallback until shared-first
lookup has passed same-project output parity.

`ExportBoundedCallGraphPcodeFlow.java` and
`ExportBoundedReverseCallGraphPcodeFlow.java` emit the same TSV row contract
while following bounded direct callees or direct callers. Optional
repeated `--priority=<rank>:<fragment>` arguments configure traversal order,
with `--default-priority=<rank>` for names that match no fragment. Repeating
the option also supports demangled symbols that contain commas. Keep
program-specific fragments in the consumer adapter; the generic exporters do
not choose title-specific names.
