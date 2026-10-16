# Ghidra function operand evidence

`ExportGhidraFunctionOperands.java` writes one `REVENGINSTR.GhidraFunctionOperand/1` JSONL row for each numeric immediate operand or referenced scalar/number datum in a selected function. Scalar values retain their bit length, signed value, and unsigned hexadecimal value. Referenced values also include their target address and data type. Call references are excluded.

Run it against an existing Ghidra project without modifying that project:

```sh
GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_function_operands.sh \
  /path/to/project project-name program-name operands.jsonl 00401000
```

The output contract is defined in [`schemas/ghidra-function-operands-v1.schema.json`](../schemas/ghidra-function-operands-v1.schema.json). A function with no numeric operands produces an empty JSONL file.
