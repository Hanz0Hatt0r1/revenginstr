# P-code instruction coverage inventory

`revenginstr-pcode-instruction-coverage` inventories machine P-code from a
`REVENGINSTR.GhidraFunctionInstructions/1` corpus. It accepts plain or gzip
JSONL and emits a compact, deterministic JSON report with the input SHA-256,
function and instruction counts, each observed P-code opcode, and machine
mnemonics for instructions that have no P-code operations.

```bash
revenginstr-pcode-instruction-coverage functions.jsonl.gz --output coverage.json
```

The report is useful for scoping a portable code generator and checking the
shape of a later backend-support matrix. It is only an inventory: opcode
presence does not prove translation semantics, and an instruction with no
P-code remains visible rather than being counted as translated. The tool makes
no source-recovery, recompilation, or behavioral-parity claim.
