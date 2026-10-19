# CFG/5 seeded-callee descendants

**Capture date:** 2026-10-20. **Target:** retail `SHIFT.exe`, SHA-256
`eca479aa2d8dbb88bc55709d91ae5c7159ae1b00fc9555d6701000c26de8aee1`.
Ghidra 12.1.2 with Java 21.0.12.1 opened the saved project read-only with
analysis disabled.

## Closed direct-call chain

Starting from the `006642a5` and `00664140` captures in the preceding
[seeded-callee replay](cfg-v5-seeded-callee-extension.md), the five direct
targets from `00664140` were batch-exported: `0066f5b0`, `007f6690`,
`0066f510`, `0064ec60`, and `0066e0e0`. Their 56 P-code rows contain 15 STOREs
and no `CALLIND`. Two additional missing leaves were reached and exported:
`00533e70` and `0062f260`, with 20 P-code rows and 10 STOREs total. The other
downstream target, `009015b0`, already had a flow in the retained selection.
All 12 direct CALL operations introduced by the nine new function bodies now
resolve to a selected P-code flow.

The caller-argument export planned 13 callee parameters and produced 10 exact
constant-offset roots. The remaining three arguments do not derive from caller
formal parameters: `006642a5` passes global addresses at its calls, while two
arguments to `009015b0` are not rooted at a formal parameter. In particular,
`00664140` writes through parameter 0 at nine byte offsets, but its caller
passes global `00bfc728`; these records do not prove that the global cannot
alias a tracked pair's parameter.

## Refreshed closure and result

The selected callee-flow input now has 106 entries (97 from the original
selection plus nine exact additions). The CFG/5 input has 110 function records.
The memory-store input has 448 records, including 34 stores from the nine added
functions. The caller-parameter-root input has 73 rows, including the 10 new
offset-root results. The effect consumer emitted 670 rows; 40 pair/call
closures reach the added chain and contain 102 functions.

The five-pair `/6` result remains four
`possible_intervening_memory_effect` rows and one
`unique_cfg_store_candidate`. No unknown operation originates in the nine new
function bodies. Existing unknown barriers remain elsewhere in the closure,
including 22 `CALLIND` sites and missing direct-call flows. This replay makes
no runtime selector or global-alias claim.

## Reproduction

From the repository root, the retained input list, per-function flows, CFG,
store facts, and roots reproduce both CLI outputs:

```bash
EVIDENCE=docs/evidence/receiver-field-access/nfs-shift-screening-20261019/scan37/replay-0041dd40
FLOW_ARGS=(--pcode-flow 0041dd40 "$EVIDENCE/caller-pcode-flow.tsv")
while IFS= read -r ENTRY; do
  if [[ -f "$EVIDENCE/closure-flows-followup/$ENTRY.tsv" ]]; then
    FLOW="$EVIDENCE/closure-flows-followup/$ENTRY.tsv"
  elif [[ -f "$EVIDENCE/field20-$ENTRY-pcode-flow.tsv" ]]; then
    FLOW="$EVIDENCE/field20-$ENTRY-pcode-flow.tsv"
  else
    FLOW="$EVIDENCE/closure-flows/$ENTRY.tsv"
  fi
  FLOW_ARGS+=(--pcode-flow "$ENTRY" "$FLOW")
done < "$EVIDENCE/interprocedural-flow-input-entries-cfg5-followup-v2.txt"

revenginstr-interprocedural-memory-effects \
  "$EVIDENCE/field-access-pairs.jsonl" \
  "$EVIDENCE/closure-function-pcode-cfg-v5-seeded-callees.jsonl" \
  "$EVIDENCE/memory-store-access-full-closure-scope-seeded-callees.jsonl" \
  "$EVIDENCE/caller-parameter-roots-cfg5-followup-v2.tsv" \
  "${FLOW_ARGS[@]}" \
  --output /tmp/interprocedural-memory-effects-v2-cfg5-seeded-callees.jsonl

revenginstr-receiver-field-store-load-dominance-audit \
  "$EVIDENCE/field-access-pairs.jsonl" \
  "$EVIDENCE/closure-function-pcode-cfg-v5-seeded-callees.jsonl" \
  --memory-store-access-jsonl \
    "$EVIDENCE/memory-store-access-full-closure-scope-seeded-callees.jsonl" \
  --interprocedural-memory-effect-jsonl \
    /tmp/interprocedural-memory-effects-v2-cfg5-seeded-callees.jsonl \
  --output /tmp/field-store-load-dominance-v6-cfg5-seeded-callees.jsonl
```

The batch acquisition record, raw multi-function flow, seven one-function flow
shards, seven-function CFG/store deltas, 13-row root plan, Ghidra argument
subtree, and 10-row root delta are retained beside the combined replay inputs.
