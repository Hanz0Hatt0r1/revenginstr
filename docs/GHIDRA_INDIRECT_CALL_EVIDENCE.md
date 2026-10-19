# Ghidra indirect-call evidence

`ExportGhidraIndirectCallEvidence.java` writes one `REVENGINSTR.GhidraIndirectCallEvidence/4` JSONL row for each `CALLIND` in one selected function. Each row pins the Ghidra program name, executable SHA-256, and ABI. The target and expression are derived from High-P-code, with a depth limit of six and explicit cycle/depth markers. Static target resolution follows only `CAST`, `COPY`, `INDIRECT`, and `LOAD` definitions to a constant address, reads one pointer-width value from program memory, and reports a target only when that value is an exact Ghidra function entry. Unsupported expressions, unreadable memory, and non-function values remain unresolved.

For an exactly resolved target, v4 also records argument positions that are the caller's exact formal parameter with no defining P-code. Prototype inference can propagate that callee parameter shape back to the caller formal. Widths and transformed arguments do not create roots; unresolved calls have an empty `parameter_roots` array.

```sh
GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_indirect_call_evidence.sh \
  /path/to/project project-name program-name indirect-calls.jsonl 00401000
```

The runner opens the existing Ghidra project read-only and disables analysis. The v4 contract is defined in [`schemas/ghidra-indirect-call-evidence-v4.schema.json`](../schemas/ghidra-indirect-call-evidence-v4.schema.json); consumers continue to accept v1, v2, and v3 rows. A function without indirect calls produces an empty JSONL file.
