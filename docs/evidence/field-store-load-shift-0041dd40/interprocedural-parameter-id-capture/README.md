# Shift `0041dd40`: positive interprocedural memory-effect replay

This targeted replay checks the `0041eda4` STORE to `0041edb2` LOAD pair across
the direct call at `0041edad` to `0088bc20`. It uses Ghidra 12.1.2 DEV and a
disposable copy of the saved `nfs_shift_vulkan_runtime_20261018` project; the
original project stayed read-only. The executable is `SHIFT.exe` with SHA-256
`eca479aa2d8dbb88bc55709d91ae5c7159ae1b00fc9555d6701000c26de8aee1`.

## Result

Parameter ID plus the exact-offset caller-root export maps
`0088bc20.param0` at call `0041edad` to caller `0041dd40.param0 + 0x7b0`.
The direct `/1` root file is empty because the argument includes an offset;
the `/2` sidecar contains the exact constant-offset root.
Parameter ID changed the saved empty signatures to
`0088bc20: __thiscall FUN_0088bc20(void * this, undefined4 param_1)` and
`0041dd40: __thiscall FUN_0041dd40(void * this, float param_1)`.

The callee has two rooted four-byte STOREs:

| Callee access | Callee offset | Caller offset after root mapping |
| --- | ---: | ---: |
| `STORE@0088bc26`, time 22 | `+0x0c` | `+0x7bc` |
| `STORE@0088bc2a`, time 35 | `+0x670` | `+0xe20` |

The tracked caller field is `param0+0x1240`, width 4. Both callee write
intervals are disjoint from `[param0+0x1240, param0+0x1244)`. The interprocedural
effect row for the call has status `no_aliasing_memory_effect`, lists both
callee STORE facts as non-aliasing, and has no unresolved operation IDs.

Before consuming that row, dominance `/7` reports
`possible_intervening_memory_effect`. With the exact call-effect sidecar, the
same pair becomes `unique_cfg_store_candidate`. The caller STORE has no
recovered value parameter, so this remains a structural CFG candidate; it does
not establish branch feasibility, runtime execution, or memory value flow.

The complete call-effect output contains 134 call-site rows: 132
`missing_callee_flow`, one `possible_aliasing_write`, and the relevant
`no_aliasing_memory_effect`. The other call sites remain conservative; the
targeted audit only removes the call at `0041edad`. Repeated replay of the pair
builder, path audit, pre-effect dominance audit, effect builder, and final
dominance audit was byte-identical for all five outputs.

## Reproduce

Copy both the `.gpr` and `.rep` files of the saved project to a disposable
directory, then run Parameter ID callee-first and caller-last:

```sh
export GHIDRA_HOME=/opt/ghidra
PROJECT_DIR=/home/pes/ghidra_projects
PROJECT_NAME=nfs_shift_vulkan_runtime_20261018
PROGRAM=SHIFT.exe
PID=nfs-shift:SHIFT.exe
EVIDENCE=docs/evidence/field-store-load-shift-0041dd40/interprocedural-parameter-id-capture
COPY=$(mktemp -d)
OUT=$(mktemp -d)

cp -a "$PROJECT_DIR/$PROJECT_NAME.gpr" "$PROJECT_DIR/$PROJECT_NAME.rep" "$COPY/"
scripts/run_ghidra_parameter_id.sh "$COPY" "$PROJECT_NAME" "$PROGRAM" \
  0088bc20 0041dd40

scripts/run_ghidra_caller_argument_subtree.sh "$COPY" "$PROJECT_NAME" "$PROGRAM" \
  "$EVIDENCE/caller-argument-plan-v2.tsv" "$OUT/caller-argument-subtree.tsv" \
  --parameter-root-output "$OUT/caller-argument-roots.tsv" \
  --parameter-offset-root-output "$OUT/caller-argument-offset-roots.tsv"

for ENTRY in 0041dd40 0088bc20; do
  scripts/run_ghidra_function_pcode_flow.sh "$COPY" "$PROJECT_NAME" "$PROGRAM" \
    "$ENTRY" "$OUT/$ENTRY-flow.tsv"
  scripts/run_ghidra_parameter_store_field.sh "$COPY" "$PROJECT_NAME" "$PROGRAM" \
    "$ENTRY" "$OUT/$ENTRY-parameter-stores.tsv" \
    --load-output "$OUT/$ENTRY-parameter-loads.tsv" \
    --memory-access-output "$OUT/$ENTRY-memory-store-access.jsonl" \
    --program-id "$PID"
  scripts/run_ghidra_function_pcode_cfg.sh "$COPY" "$PROJECT_NAME" "$PROGRAM" \
    "$OUT/$ENTRY-cfg-v4.jsonl" "$PID" "$ENTRY" \
    --physical-memory-metadata --indirect-effect-links
done
```

For a repeat analyzer run against the frozen inputs, use the commands below.
They write outputs to the temporary `OUT` folder:

```sh
uv run --no-sync revenginstr-receiver-field-access-pairs \
  "$EVIDENCE/caller-parameter-stores.tsv" "$EVIDENCE/caller-parameter-loads.tsv" \
  --program-id nfs-shift:SHIFT.exe \
  --memory-store-access-jsonl "$EVIDENCE/caller-memory-store-access.jsonl" \
  --output "$OUT/field-access-pairs.jsonl"
python - "$OUT/field-access-pairs.jsonl" "$OUT/field-access-pair-target.jsonl" <<'PY'
import json, sys
from pathlib import Path
rows = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines()]
matches = [row for row in rows if "0041eda4" in row["graph_id"] and "0041edb2" in row["graph_id"]]
assert len(matches) == 1
Path(sys.argv[2]).write_text(json.dumps(matches[0], sort_keys=True) + "\n")
PY
uv run --no-sync revenginstr-receiver-field-store-load-audit \
  "$OUT/field-access-pair-target.jsonl" "$EVIDENCE/function-pcode-cfg-v4.jsonl" \
  --output "$OUT/path-audit.jsonl"
uv run --no-sync revenginstr-receiver-field-store-load-dominance-audit \
  "$OUT/field-access-pair-target.jsonl" "$EVIDENCE/function-pcode-cfg-v4.jsonl" \
  --memory-store-access-jsonl "$EVIDENCE/memory-store-access.jsonl" \
  --output "$OUT/dominance-before.jsonl"
uv run --no-sync revenginstr-interprocedural-memory-effects \
  "$OUT/field-access-pair-target.jsonl" "$EVIDENCE/function-pcode-cfg-v4.jsonl" \
  "$EVIDENCE/memory-store-access.jsonl" "$EVIDENCE/caller-argument-offset-roots.tsv" \
  --pcode-flow 0041dd40 "$EVIDENCE/caller-pcode-flow.tsv" \
  --pcode-flow 0088bc20 "$EVIDENCE/callee-pcode-flow.tsv" \
  --output "$OUT/interprocedural-memory-effects.jsonl"
uv run --no-sync revenginstr-receiver-field-store-load-dominance-audit \
  "$OUT/field-access-pair-target.jsonl" "$EVIDENCE/function-pcode-cfg-v4.jsonl" \
  --memory-store-access-jsonl "$EVIDENCE/memory-store-access.jsonl" \
  --interprocedural-memory-effect-jsonl "$OUT/interprocedural-memory-effects.jsonl" \
  --output "$OUT/dominance-after.jsonl"
```

The full 87-row pair output is retained alongside the selected target pair.
Repeated analyzer replay produced byte-identical results. The outputs and all
captured inputs are hash-pinned in [`SHA256SUMS`](SHA256SUMS).
