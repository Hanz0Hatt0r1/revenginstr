# Ghidra function instruction export

ExportGhidraFunctionInstructions.java exports selected functions as JSONL using
the REVENGINSTR.GhidraFunctionInstructions/1 schema. Each row contains
instruction bytes and text, operands, references, control-flow destinations,
and machine P-code operations with their varnodes. It does not decompile
functions or change the analyzed program.

Run against an existing Ghidra project:

    GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_function_instructions.sh \
      /path/to/project ProjectName program \
      /tmp/function-instructions.jsonl 00401000 00402000

The exporter accepts hexadecimal function entry addresses, optionally prefixed
with 0x or FUN_. Missing targets produce a found: false row and make the
headless command fail. Validate each JSONL row against
schemas/ghidra-function-instructions-v1.schema.json.
