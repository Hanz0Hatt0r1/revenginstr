# Ghidra function instruction export

ExportGhidraFunctionInstructions.java exports selected functions as JSONL using
the REVENGINSTR.GhidraFunctionInstructions/1 schema. Each row contains
instruction bytes and text, operands, references, control-flow destinations,
and machine P-code operations with their varnodes. It does not decompile
functions or change the analyzed program. The targeted format is unchanged.

Run against an existing Ghidra project:

    GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_function_instructions.sh \
      /path/to/project ProjectName program \
      /tmp/function-instructions.jsonl 00401000 00402000

The exporter accepts hexadecimal function entry addresses, optionally prefixed
with 0x or FUN_. `entry:<address>` explicitly exports an entrypoint even when
Ghidra has not created a Function record there. Such rows use an `ENTRY_`
function name and a null calling convention; a bounded pseudo-disassembly
follows direct control flow without modifying the project. Missing ordinary or
entrypoint targets produce a found: false row and make the headless command
fail. Validate each JSONL row against
schemas/ghidra-function-instructions-v1.schema.json.

For defined functions, the exporter also repairs one conservative CFG case:
when a direct `CALL` is marked `CALL_TERMINATOR` but its defined callee contains
a P-code `RETURN`, it follows the physical fallthrough with Ghidra's
`PseudoDisassembler`, adds reachable instructions until they join known body
code or reach a terminator, and reports the call as `UNCONDITIONAL_CALL` with
its return address. Recovery is bounded to 4 KiB per continuation and stops at
another known function. This keeps the JSONL shape unchanged. The function
`size` remains Ghidra's original body size, so it may be smaller than the
instruction bytes after a continuation was recovered.

For a complete program corpus or deterministic address-ordered shard, use
`--all`. Gzip is selected by the output suffix; the exporter writes a sidecar
manifest with program identity, ordinal range, counts, completeness and output
SHA-256:

    GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_function_instructions.sh \
      /path/to/project ProjectName program /path/to/functions-000000.jsonl.gz --all 0 1000

    GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_function_instructions.sh \
      /path/to/project ProjectName program /path/to/functions-001000.jsonl.gz --all 1000 1000

Offset and limit count entries in Ghidra's ascending function iterator. A
limit of 0 exports the remainder. Omit offset and limit to export the whole
program in one file. The exporter writes one JSONL row at a time and scans each
function's instruction iterator twice so very large functions do not accumulate
their full JSON representation in memory. Keep full proprietary output outside
Git; commit hashes, manifests or compact derived evidence instead.
