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

Load rows join by exact function/address/time and `LOAD` opcode. The field-load
exporter's `def:LOAD@address:time:size` output token is accepted as an alias of
the P-code flow `def:address:time:size` token when the full suffix matches; the
P-code token remains the one used for subsequent def-use joins.

```sh
revenginstr-state-machine-candidates \
  cfg-v3.jsonl pcode-flow.tsv parameter-loads.tsv memory-stores.jsonl \
  --max-candidates 100000 --output state-machine-candidates.json
```

When the P-code or sidecar captures cover more functions than the CFG input,
select the exact function population explicitly. Repeat the option for several
functions:

```sh
revenginstr-state-machine-candidates \
  cfg-v3.jsonl pcode-flow.tsv parameter-loads.tsv memory-stores.jsonl \
  --function-entry 00401000 --function-entry 00402000 \
  --output state-machine-candidates.json
```

Selection is applied consistently to CFG, P-code, loads, and stores. The report
continues to pin each full input artifact, and source record indices refer to
the original unfiltered inputs. Selected functions must still have matching
CFG/P-code operation populations and complete STORE sidecars.

Without `--function-entry`, the tool emits
[`StateMachineCandidateAudit/1`](../schemas/state-machine-candidate-audit-v1.schema.json).
With function selection it emits
[`StateMachineCandidateAudit/2`](../schemas/state-machine-candidate-audit-v2.schema.json),
which records the sorted selected entries even when there are no candidates.
Each row remains only a structural candidate. It does not identify branch
true/false polarity, establish path feasibility, recover runtime state values,
or prove that a write is a semantic state transition. Cross-function field
sharing, switch-table recovery, transition graphs, edge confidence, and
consumer evaluation remain open roadmap work.

`branch.write_reachable_successor_index` is the CFG block index value of the
unique successor that reaches the write, not its array position in
`successor_block_indices`.

The tool is also available as the `state-machine-candidates` benchmark stage.
It plans no probes and makes no semantic labels.
