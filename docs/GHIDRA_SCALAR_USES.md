# Ghidra exact scalar uses

Export instructions containing an exact caller-selected unsigned scalar in an
operand. Each matching instruction appears once, with its first matching
operand, function identity when available, and a coarse mnemonic-based usage
class.

The TSV-independent JSONL row contract is
schemas/ghidra-scalar-uses-v1.schema.json. These rows are candidate inventory
only: matching a numeric scalar does not prove that it is an object identity,
field access, writer, or semantic constant.

Run against an already analyzed program:

    GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_scalar_uses.sh       /path/to/projects project-name program-name /tmp/scalar-uses.jsonl 0x2a

The runner uses recursive program lookup, read-only/no-analysis mode, and an
isolated script directory. The scalar value is supplied by the consumer.
