# High-P-code function CFG export

`GhidraFunctionPcodeCFG/1` exports basic blocks, their ordered High-P-code
operations, and outgoing control-flow edges for explicitly requested
functions. Each row also carries a caller-supplied opaque `program_id`; the
field store/load path audit requires that identifier and the function entry to
match the pair graph exactly.

Run it against an existing analyzed Ghidra project:

```bash
GHIDRA_HOME=/opt/ghidra \
  scripts/run_ghidra_function_pcode_cfg.sh \
  /path/to/projects project-name program-name function-pcode-cfg.jsonl \
  'analysis:opaque-id' 00401000 00402000
```

The project is opened read-only with analysis disabled. The runner requests
only the listed function entries. Basic-block indices follow Ghidra's returned
block order; successor indices are sorted, and operation rows follow each
block's P-code iterator order. The exporter requests the High-P-code syntax
tree without generating unused C-code markup. Operation addresses and sequence
times use the same High-P-code identity as the parameter store/load exporter.

The schema is [`GhidraFunctionPcodeCFG/1`](../schemas/ghidra-function-pcode-cfg-v1.schema.json).
`program_id` is an opaque join key, not a binary fingerprint or a game label;
use the same value when building the receiver field-access pair graphs.

Pass `--memory-metadata` after the requested entries to emit
`GhidraFunctionPcodeCFG/2` instead. Version 2 adds the exact entry block index
and, for every `LOAD`/`STORE`, its P-code address-space name and access width in
bytes. Unknown metadata is `null`; the conservative dominance audit fails
closed on missing space or width. The default remains version 1 for existing
consumers.

```bash
GHIDRA_HOME=/opt/ghidra \
  scripts/run_ghidra_function_pcode_cfg.sh \
  /path/to/projects project-name program-name function-pcode-cfg.jsonl \
  'analysis:opaque-id' 00401000 --memory-metadata
```

Version 2 is defined by
[`GhidraFunctionPcodeCFG/2`](../schemas/ghidra-function-pcode-cfg-v2.schema.json).
It still exports CFG and operation metadata only; it does not resolve pointer
aliases, prove branch feasibility, or identify runtime values.

Pass `--physical-memory-metadata` to emit version 3. It includes all version 2
fields and adds the physical address-space name and pointer width for each
`LOAD`/`STORE` (both nullable when Ghidra cannot resolve them). For non-memory
operations these fields are null. Version 3 lets structural audits keep a
possible effect when distinct logical spaces share a physical space, and
exclude a store only when its known physical space differs from the tracked
access. It still does not resolve pointer bases, offsets, overlays at runtime,
or branch feasibility. The shared reader rejects conflicting physical-space
or pointer-width metadata for repeated operations in the same logical space.

Version 3 is defined by
[`GhidraFunctionPcodeCFG/3`](../schemas/ghidra-function-pcode-cfg-v3.schema.json).

The runner checks that the exporter emitted its format completion marker in
addition to checking Ghidra's process exit. Some Ghidra versions can log a
post-script exception while returning a zero exit status; missing completion
markers therefore fail the runner.

For metadata exports, `--skip-missing-entry-blocks` lets a batch continue when
Ghidra returns a High-P-code graph with no block starting at the function entry.
The default still fails the export. Skipped functions have no CFG row, and the
exporter reports each omitted entry with
`GHIDRA_FUNCTION_PCODE_CFG_SKIPPED_ENTRY=<address> reason=entry_block_not_found`
plus exported/skipped counts. Preserve that log with the JSONL: a skipped CFG
is missing evidence and must remain a barrier in downstream audits.
