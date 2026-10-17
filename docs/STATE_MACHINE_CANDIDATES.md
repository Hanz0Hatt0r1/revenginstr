# State-machine structural candidates

`revenginstr-state-machine-candidates` emits a bounded, single-function
structural audit. It joins `GhidraFunctionPcodeCFG/3`,
`GhidraFunctionPcodeFlow/1`, `GhidraParameterLoadField/1`, and
`GhidraMemoryStoreAccess/1` by exact program, function, address, time, opcode,
and value-token keys. CFG and P-code operation populations must match, and the
memory sidecar must account for every P-code `STORE` in the selected functions.

The initial pattern requires a parameter-rooted field `LOAD` to feed a
comparison, the comparison result to feed a terminal `CBRANCH` with two CFG
successors through its condition operand, and a `STORE` to the same parameter
and byte offset to be reachable from exactly one successor. Inputs are
read-only; the report records their hashes and source record indices. Broken
joins fail closed.

```sh
revenginstr-state-machine-candidates \
  cfg-v3.jsonl pcode-flow.tsv parameter-loads.tsv memory-stores.jsonl \
  --max-candidates 100000 --output state-machine-candidates.json
```

Each row in [`StateMachineCandidateAudit/1`](../schemas/state-machine-candidate-audit-v1.schema.json)
is only a structural candidate. It does not identify branch true/false
polarity, establish path feasibility, recover runtime state values, or prove
that a write is a semantic state transition. Cross-function field sharing,
switch-table recovery, transition graphs, edge confidence, and consumer
evaluation remain open roadmap work.

The tool is also available as the `state-machine-candidates` benchmark stage.
It plans no probes and makes no semantic labels.
