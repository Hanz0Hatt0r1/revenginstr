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
`tests/fixtures/receiver-flow-pcode.tsv` adds legal synthetic LOAD/COPY/RETURN
and CALL/COPY/RETURN sequences used by the receiver load-return and call-return
dataflow tests; all six operation rows are validated against the same schema.

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

The runner also requires the exporter's `GhidraFunctionPcodeFlow/1` completion
marker. Ghidra can return a zero process status after a post-script exception;
the missing marker makes that run fail closed.

`ExportBoundedCallGraphPcodeFlow.java` and
`ExportBoundedReverseCallGraphPcodeFlow.java` emit the same TSV row contract
while following bounded direct callees or direct callers. Optional
repeated `--priority=<rank>:<fragment>` arguments configure traversal order,
with `--default-priority=<rank>` for names that match no fragment. Repeating
the option also supports demangled symbols that contain commas. Keep
program-specific fragments in the consumer adapter; the generic exporters do
not choose title-specific names.

## Direct-call memory-effect facts

`revenginstr-direct-call-memory-effects` compares a caller's one-function
P-code flow TSV with optional one-function TSVs for exact resolved direct
callees:

```sh
revenginstr-direct-call-memory-effects caller-flow.tsv \
  --program-id 'consumer:analysis-id' \
  --callee-flow 00402000 helper-flow.tsv \
  --output direct-call-memory-effects.jsonl
```

Repeat `--callee-flow ENTRY TSV` for each direct callee whose body was exported.
Only a non-empty callee export containing operations from the known write-free
P-code set and no nested call or unknown operation receives
`no_explicit_memory_write`. A callee with a `STORE` reports
`explicit_memory_write`; missing flow, nested or unmodeled operations, and
indirect calls remain unresolved effects. The tool does not recurse through
calls or assign source-level purity. Its output,
`GhidraDirectCallMemoryEffect/1`, pins the caller P-code artifact and row plus
the callee P-code hash and operation count.
The CLI caps call sites at 100,000, aggregate P-code flow inputs at 64 MiB and
one million operations by default; lower or higher positive limits can be
supplied explicitly for a consumer's frozen run.

This sidecar may be combined with `GhidraMemoryStoreAccess/1` and CFG/3 in the
versioned dominance `/3` audit. Only exact `CALL` operations with a complete
write-free direct-callee row can be removed as barriers; `CALLIND`, unresolved
calls, and every other possible effect stay conservative.
