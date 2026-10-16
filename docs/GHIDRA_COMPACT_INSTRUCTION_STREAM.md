# Ghidra compact instruction stream

Export every decoded instruction in program address order using a compact,
versioned JSONL format. The first row is a program identity header; following
rows contain instruction address, mnemonic, rendered operands, flow type, and
flow targets. The schema is
`schemas/ghidra-compact-instruction-stream-v1.schema.json`.

Output paths ending in `.gz` are gzip-compressed. Compression changes storage
only; it does not change the canonical row contract.

Run against an already analyzed program:

```bash
GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_compact_instruction_stream.sh \
  /path/to/projects project-name program-name /tmp/instructions.jsonl.gz
```

The runner uses read-only/no-analysis mode and an isolated script directory.
Executable identity fields describe the current Ghidra program; they do not
establish that it is an authoritative copy of a particular binary.
