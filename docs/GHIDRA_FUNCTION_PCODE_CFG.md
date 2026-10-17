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
block's P-code iterator order. Operation addresses and sequence times use the
same High-P-code identity as the parameter store/load exporter.

The schema is [`GhidraFunctionPcodeCFG/1`](../schemas/ghidra-function-pcode-cfg-v1.schema.json).
`program_id` is an opaque join key, not a binary fingerprint or a game label;
use the same value when building the receiver field-access pair graphs.
