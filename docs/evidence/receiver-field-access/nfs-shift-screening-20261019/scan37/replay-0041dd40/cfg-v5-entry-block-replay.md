# CFG/5 entry-block replay

The CFG/4 export left two boundaries in the captured call closure: `006642a0`
had no block at the function entry, and `0090e864` had two. CFG/5 exports the
caller plus all 100 functions from the retained `closure-pcode-flow.tsv`
selection and records all matching entry blocks. It skips none: `006642a0` has
`entry_block_indices: []`, while `0090e864` has `entry_block_indices: [0, 1]`.
The other 99 functions have one entry block each.

The capture was made from the original SHIFT Ghidra 12.1.2 development project
with Java 21.0.12.1 and the runner's read-only, `-noanalysis` settings. The
executable is the same SHA-256-pinned binary recorded for scan37. All 101 rows validate against
[`GhidraFunctionPcodeCFG/5`](../../../../../../schemas/ghidra-function-pcode-cfg-v5.schema.json)
and the RevEngInstr CFG reader. The CFG reader also checks that the root list
exactly enumerates every block whose start address equals the function entry.
This is acquisition coverage evidence; it does not change the earlier field
pair classifications or claim that any path is feasible at runtime.

The raw export is [`closure-function-pcode-cfg-v5.jsonl`](closure-function-pcode-cfg-v5.jsonl),
SHA-256 `1845690e1b40c5f1ba4de087b6c464f94cc78e81655cf7eca04c41e6d460760c`.
The source flow selection is pinned in the parent evidence manifest.

The interprocedural memory effects were rebuilt against this CFG/5 export using
the retained caller flow, 97 closure flows, memory-store facts, and caller
parameter roots. All 670 rows validate against `GhidraInterproceduralMemoryEffect/2`.
The prior CFG/4 replay had 40 effect rows containing `MISSING_CFG`; CFG/5
removes those markers. The 40 rows still retain `CALLIND` and `STORE` effects,
so their statuses remain `unknown_effect`.

The resulting `FieldStoreLoadDominanceAudit/6` has four
`possible_intervening_memory_effect` rows and one `unique_cfg_store_candidate`,
the same five semantic results as the CFG/4 replay. After omitting the
provenance objects, the CFG/5 audit rows have the same semantic payloads as
the earlier rows. The sidecars are
[`interprocedural-memory-effects-v2-cfg5.jsonl`](interprocedural-memory-effects-v2-cfg5.jsonl),
SHA-256 `c2f40eabe2efb2454901eed2ac5de672438271e07a9fe71ed4a09930e7e4c1ae`,
and [`field-store-load-dominance-v6-cfg5.jsonl`](field-store-load-dominance-v6-cfg5.jsonl),
SHA-256 `adf04353cbb152fd7a72dd8a81e46ed0478dea7f98db68c668d371bb833e00cd`.

Rebuild the CFG/5 sidecars from the repository root after installing the
project's CLI entry points:

```sh
EVIDENCE=docs/evidence/receiver-field-access/nfs-shift-screening-20261019/scan37/replay-0041dd40
EFFECT_ARGS=(
  "$EVIDENCE/field-access-pairs.jsonl"
  "$EVIDENCE/closure-function-pcode-cfg-v5.jsonl"
  "$EVIDENCE/memory-store-access-full-closure-scope.jsonl"
  "$EVIDENCE/caller-parameter-roots-closure-v2.tsv"
  --pcode-flow 0041dd40 "$EVIDENCE/caller-pcode-flow.tsv"
)
while IFS= read -r ENTRY; do
  EFFECT_ARGS+=(--pcode-flow "$ENTRY" "$EVIDENCE/closure-flows/$ENTRY.tsv")
done < "$EVIDENCE/interprocedural-flow-input-entries.txt"

revenginstr-interprocedural-memory-effects "${EFFECT_ARGS[@]}" \
  --output /tmp/interprocedural-memory-effects-v2-cfg5.jsonl
revenginstr-receiver-field-store-load-dominance-audit \
  "$EVIDENCE/field-access-pairs.jsonl" \
  "$EVIDENCE/closure-function-pcode-cfg-v5.jsonl" \
  --memory-store-access-jsonl "$EVIDENCE/memory-store-access-full-closure-scope.jsonl" \
  --interprocedural-memory-effect-jsonl /tmp/interprocedural-memory-effects-v2-cfg5.jsonl \
  --output /tmp/field-store-load-dominance-v6-cfg5.jsonl
```

To reproduce from the repository root on the same Ghidra project:

```sh
EVIDENCE=docs/evidence/receiver-field-access/nfs-shift-screening-20261019/scan37/replay-0041dd40
mapfile -t ENTRIES < <({ printf '%s\n' 0041dd40; tail -n +2 "$EVIDENCE/closure-pcode-flow.tsv" | cut -f1; } | sort -u)

GHIDRA_HOME=/opt/ghidra JAVA_HOME=/usr/lib/jvm/java-21-openjdk \
  PATH=/usr/lib/jvm/java-21-openjdk/bin:$PATH \
  scripts/run_ghidra_function_pcode_cfg.sh \
  /home/pes/ghidra_projects/shift shift SHIFT.exe \
  /tmp/closure-function-pcode-cfg-v5.jsonl nfs-shift:SHIFT.exe \
  "${ENTRIES[@]}" --entry-block-indices
```
