# Ghidra instruction slices

Export bounded machine-instruction context around caller-selected addresses,
including disassembly, references, control-flow edges and machine P-code. The
versioned JSONL row contract is
`schemas/ghidra-instruction-slice-v1.schema.json`.

Targets use `address[:hex-length]`; omitted lengths default to `0x80`. Multiple
targets produce rows in the supplied order. `exact_instruction_at_start` and
`instruction_count` make missing or empty slices explicit. A slice is decoder
evidence, not proof of a semantic owner or data-flow relationship.

Run against an already analyzed program:

```bash
GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_instruction_slices.sh \
  /path/to/projects project-name program-name /tmp/slices.jsonl \
  0x00401000:0x80 0x00402000:0x40
```

The runner uses recursive program lookup, read-only/no-analysis mode, an
isolated script directory, and a configurable headless timeout.
