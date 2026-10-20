# Shift `0041dd40`: memory-only store/load candidates

This fresh read-only replay checks `FieldStoreLoadDominanceAudit/7` on one
function in `SHIFT.exe` (`nfs-shift:SHIFT.exe`, SHA-256
`eca479aa2d8dbb88bc55709d91ae5c7159ae1b00fc9555d6701000c26de8aee1`). The
saved Ghidra project is `nfs_shift_vulkan_runtime_20261018`; exports used
Ghidra 12.1.2 DEV and the repository's `-readOnly -noanalysis` runners. The
capture and replay outputs are in [`capture/`](capture/); their hashes are
pinned in [`SHA256SUMS`](capture/SHA256SUMS).

## Replay result

The exporter produced 2,645 P-code flow operations, 76 parameter loads, 53
memory-store facts (51 rooted at a constant offset), and no
`ParameterStoreField/1` rows. Pairing the exact roots and offsets produced 87
graphs. The path audit reports 12 `candidate_path_compatible`, 10
`intervening_store_or_call`, and 65 `no_cfg_path` rows. The stricter `/7`
dominance audit reports 12 `unique_cfg_store_candidate`, 10
`possible_intervening_memory_effect`, and 65 `store_not_dominating_load` rows.

For example, `STORE@0041e466` at time 2223 and `LOAD@0041e4ae` at time 2511
both access parameter 0 plus `0x3f4`, with width 4. The store has no recovered
value parameter, so the candidate has no value-source edge. The CFG witness is
blocks `[76, 78, 79, 80]`; there is no intervening memory-effect path. The
audit records 52 comparisons against the function's rooted store facts. The
other unique rows are additional structural candidates in the same function,
not runtime observations or proof of memory reaching-definition. The export
and analyzer replay were repeated; the three analyzer outputs were
byte-identical.

## Reproduce

```sh
export GHIDRA_HOME=/opt/ghidra
PROJECT_DIR=/home/pes/ghidra_projects
PROJECT_NAME=nfs_shift_vulkan_runtime_20261018
PROGRAM=SHIFT.exe
ENTRY=0041dd40
CAPTURE=docs/evidence/field-store-load-shift-0041dd40/capture

scripts/run_ghidra_function_pcode_flow.sh "$PROJECT_DIR" "$PROJECT_NAME" "$PROGRAM" \
  "$ENTRY" "$CAPTURE/function-pcode-flow.tsv"
scripts/run_ghidra_parameter_store_field.sh "$PROJECT_DIR" "$PROJECT_NAME" "$PROGRAM" \
  "$ENTRY" "$CAPTURE/parameter-stores.tsv" \
  --load-output "$CAPTURE/parameter-loads.tsv" \
  --memory-access-output "$CAPTURE/memory-store-access.jsonl" \
  --program-id nfs-shift:SHIFT.exe
scripts/run_ghidra_function_pcode_cfg.sh "$PROJECT_DIR" "$PROJECT_NAME" "$PROGRAM" \
  "$CAPTURE/function-pcode-cfg-v4.jsonl" nfs-shift:SHIFT.exe "$ENTRY" \
  --physical-memory-metadata --indirect-effect-links

uv run revenginstr-receiver-field-access-pairs \
  "$CAPTURE/parameter-stores.tsv" "$CAPTURE/parameter-loads.tsv" \
  --program-id nfs-shift:SHIFT.exe \
  --memory-store-access-jsonl "$CAPTURE/memory-store-access.jsonl" \
  --output "$CAPTURE/field-access-pairs.jsonl"
uv run revenginstr-receiver-field-store-load-audit \
  "$CAPTURE/field-access-pairs.jsonl" "$CAPTURE/function-pcode-cfg-v4.jsonl" \
  --output "$CAPTURE/path-audit.jsonl"
uv run revenginstr-receiver-field-store-load-dominance-audit \
  "$CAPTURE/field-access-pairs.jsonl" "$CAPTURE/function-pcode-cfg-v4.jsonl" \
  --memory-store-access-jsonl "$CAPTURE/memory-store-access.jsonl" \
  --output "$CAPTURE/dominance-v7.jsonl"
```

This validates the single-function, memory-only store boundary. A separate
Parameter ID replay checks one positive interprocedural call-effect case using
fresh caller roots and callee memory facts; see
[`interprocedural-parameter-id-capture`](interprocedural-parameter-id-capture/README.md).
A follow-up screen covers five adjacent call/pair sites; only the complete
`0088bc20` closure promotes, while four nested `0088d1d0` closures remain
conservative. See [`call-series-screen`](call-series-screen/README.md).
