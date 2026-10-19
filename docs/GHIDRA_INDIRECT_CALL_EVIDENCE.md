# Ghidra indirect-call evidence

`ExportGhidraIndirectCallEvidence.java` writes one `REVENGINSTR.GhidraIndirectCallEvidence/2` JSONL row for each `CALLIND` in one selected function. Each row pins the Ghidra program name, executable SHA-256, and ABI. The target and expression are derived from High-P-code, with a depth limit of six and explicit cycle/depth markers. The exporter records no decompiler C, instruction bytes, strings, or consumer labels.

```sh
GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_indirect_call_evidence.sh \
  /path/to/project project-name program-name indirect-calls.jsonl 00401000
```

The runner opens the existing Ghidra project read-only and disables analysis. The v2 contract is defined in [`schemas/ghidra-indirect-call-evidence-v2.schema.json`](../schemas/ghidra-indirect-call-evidence-v2.schema.json); consumers continue to accept legacy v1 rows. A function without indirect calls produces an empty JSONL file.
