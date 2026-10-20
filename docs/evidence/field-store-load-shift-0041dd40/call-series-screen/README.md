# Shift `0041dd40`: adjacent field pairs across direct calls

This capture screens five adjacent memory-only store/load pairs in `SHIFT.exe`
(`nfs-shift:SHIFT.exe`, SHA-256
`eca479aa2d8dbb88bc55709d91ae5c7159ae1b00fc9555d6701000c26de8aee1`). The
Ghidra 12.1.2 DEV exports and Parameter ID work used a disposable copy of
`nfs_shift_vulkan_runtime_20261018`; the original saved project stayed
read-only. Raw P-code, CFG/4, memory facts, roots, analyzer inputs, outputs,
and logs are retained here.

## Result

Each caller-side target call has an exact root mapping from its callee
`param0` to `0041dd40.param0 + 0x7b0`. The helper's own rooted STOREs are
disjoint from the paired four-byte field after that offset is applied:

| Tracked field | Store → load | Call → callee | Helper STORE offsets after root mapping | `/7` after `/2` effects |
| ---: | --- | --- | --- | --- |
| `+0x1230` | `0041ea5d` → `0041ea6b` | `0041ea66` → `0088d550` | `+0xe60`, `+0xe84` | `possible_intervening_memory_effect` |
| `+0x1234` | `0041eb31` → `0041eb3f` | `0041eb3a` → `0088d5d0` | `+0x7bc`, `+0xe64`, `+0xe84` | `possible_intervening_memory_effect` |
| `+0x1238` | `0041ec05` → `0041ec13` | `0041ec0e` → `0088d620` | `+0x7bc`, `+0xe68`, `+0xe84` | `possible_intervening_memory_effect` |
| `+0x123c` | `0041ecd9` → `0041ece7` | `0041ece2` → `0088d670` | `+0x7bc`, `+0xe6c`, `+0xe84` | `possible_intervening_memory_effect` |
| `+0x1240` | `0041eda4` → `0041edb2` | `0041edad` → `0088bc20` | `+0x7bc`, `+0xe20` | `unique_cfg_store_candidate` |

Before interprocedural effects, all five rows were
`possible_intervening_memory_effect`. The `/2` builder proves the `0088bc20`
call has no aliasing STOREs or unknown operations. That call is the only
intervening effect on the `+0x1240` witness, so the targeted `/7` row becomes
`unique_cfg_store_candidate`.

The other four helper closures reach `0088d1d0`. Its P-code contains three
STORE facts: two rooted at `param0+0x5b4` and one unresolved destination. The
nested argument plan finds one exact `0088d1d0.param0` root at
`0088d550@0088d5af` (`0088d550.param0+0`); it finds no exact roots at the
other four `0088d1d0` call sites. The shared closure therefore retains all
three STOREs as possible aliases. `0088d1d0` also contains 24 direct calls
without supplied callee flows. Those barriers remain `unknown_effect`, and
the four paired audits stay conservative.

Across the five selected pairs, the complete effect output has 670 rows:
620 `missing_callee_flow`, 40 `unknown_effect`, five
`no_aliasing_memory_effect`, and five `possible_aliasing_write`. Replaying the
pair builder, pair selection, path audit, both dominance audits, and effect
builder produced six byte-identical derived outputs. These are structural
results only; they do not prove branch feasibility, runtime execution, or
memory value flow. The separate positive-only replay is documented in
[`interprocedural-parameter-id-capture`](../interprocedural-parameter-id-capture/README.md).

## Reproduce the analyzer replay

To reproduce the Ghidra inputs, copy the original project to a disposable
directory and run Parameter ID for the direct callees before the caller, then
for the two nested callees and their parents:

```sh
export GHIDRA_HOME=/opt/ghidra
PROJECT_DIR=/home/pes/ghidra_projects
PROJECT_NAME=nfs_shift_vulkan_runtime_20261018
PROGRAM=SHIFT.exe
COPY=$(mktemp -d)
OUT=$(mktemp -d)
cp -a "$PROJECT_DIR/$PROJECT_NAME.gpr" "$PROJECT_DIR/$PROJECT_NAME.rep" "$COPY/"

for pass in 1 2; do
  scripts/run_ghidra_parameter_id.sh "$COPY" "$PROJECT_NAME" "$PROGRAM" \
    0088d550 0088d5d0 0088d620 0088d670 0088bc20 0041dd40 \
    >"$OUT/parameter-id-top-pass$pass.log" 2>&1
done
for pass in 1 2; do
  scripts/run_ghidra_parameter_id.sh "$COPY" "$PROJECT_NAME" "$PROGRAM" \
    0088ba20 0088d1d0 0088d550 0088d5d0 0088d620 0088d670 0041dd40 \
    >"$OUT/parameter-id-full-pass$pass.log" 2>&1
done
```

The included `caller-argument-plan-v2.tsv` and `nested-call-plan-v2.tsv`
produce the saved `/1` and `/2` root sidecars with
`scripts/run_ghidra_caller_argument_subtree.sh`. Export all eight functions in
`functions/` using `run_ghidra_function_pcode_flow.sh`,
`run_ghidra_parameter_store_field.sh`, and
`run_ghidra_function_pcode_cfg.sh` with `--physical-memory-metadata
--indirect-effect-links`. Concatenate their CFG and memory-store outputs in
the order used by `function-pcode-cfg-v4.jsonl` and `memory-store-access.jsonl`.

Run from the repository root. The frozen `functions/` captures, combined
CFG/4, combined memory facts, and combined exact-offset roots are the analyzer
inputs. The commands write outputs to a temporary directory:

```sh
EVIDENCE=docs/evidence/field-store-load-shift-0041dd40/call-series-screen
OUT=$(mktemp -d)

uv run --no-sync revenginstr-receiver-field-access-pairs \
  "$EVIDENCE/functions/0041dd40/parameter-stores.tsv" \
  "$EVIDENCE/functions/0041dd40/parameter-loads.tsv" \
  --program-id nfs-shift:SHIFT.exe \
  --memory-store-access-jsonl "$EVIDENCE/functions/0041dd40/memory-store-access.jsonl" \
  --output "$OUT/field-access-pairs.jsonl"
python - "$OUT/field-access-pairs.jsonl" "$OUT/field-access-pair-targets.jsonl" <<'PY'
import json, sys
from pathlib import Path
rows = [json.loads(line) for line in Path(sys.argv[1]).read_text().splitlines()]
sites = (("0041ea5d", "0041ea6b"), ("0041eb31", "0041eb3f"),
         ("0041ec05", "0041ec13"), ("0041ecd9", "0041ece7"),
         ("0041eda4", "0041edb2"))
selected = []
for store, load in sites:
    matches = [row for row in rows if store in row["graph_id"] and load in row["graph_id"]]
    assert len(matches) == 1
    selected.extend(matches)
Path(sys.argv[2]).write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in selected))
PY
uv run --no-sync revenginstr-receiver-field-store-load-audit \
  "$OUT/field-access-pair-targets.jsonl" "$EVIDENCE/function-pcode-cfg-v4.jsonl" \
  --output "$OUT/path-audit.jsonl"
uv run --no-sync revenginstr-receiver-field-store-load-dominance-audit \
  "$OUT/field-access-pair-targets.jsonl" "$EVIDENCE/function-pcode-cfg-v4.jsonl" \
  --memory-store-access-jsonl "$EVIDENCE/memory-store-access.jsonl" \
  --output "$OUT/dominance-before.jsonl"
uv run --no-sync revenginstr-interprocedural-memory-effects \
  "$OUT/field-access-pair-targets.jsonl" "$EVIDENCE/function-pcode-cfg-v4.jsonl" \
  "$EVIDENCE/memory-store-access.jsonl" "$EVIDENCE/caller-argument-offset-roots.tsv" \
  --pcode-flow 0041dd40 "$EVIDENCE/functions/0041dd40/function-pcode-flow.tsv" \
  --pcode-flow 0088d550 "$EVIDENCE/functions/0088d550/function-pcode-flow.tsv" \
  --pcode-flow 0088d5d0 "$EVIDENCE/functions/0088d5d0/function-pcode-flow.tsv" \
  --pcode-flow 0088d620 "$EVIDENCE/functions/0088d620/function-pcode-flow.tsv" \
  --pcode-flow 0088d670 "$EVIDENCE/functions/0088d670/function-pcode-flow.tsv" \
  --pcode-flow 0088bc20 "$EVIDENCE/functions/0088bc20/function-pcode-flow.tsv" \
  --pcode-flow 0088ba20 "$EVIDENCE/functions/0088ba20/function-pcode-flow.tsv" \
  --pcode-flow 0088d1d0 "$EVIDENCE/functions/0088d1d0/function-pcode-flow.tsv" \
  --output "$OUT/interprocedural-memory-effects.jsonl"
uv run --no-sync revenginstr-receiver-field-store-load-dominance-audit \
  "$OUT/field-access-pair-targets.jsonl" "$EVIDENCE/function-pcode-cfg-v4.jsonl" \
  --memory-store-access-jsonl "$EVIDENCE/memory-store-access.jsonl" \
  --interprocedural-memory-effect-jsonl "$OUT/interprocedural-memory-effects.jsonl" \
  --output "$OUT/dominance-after.jsonl"
```

The root-export and Parameter ID commands are recorded in the logs and
reproducible from `caller-argument-plan-v2.tsv` and
`nested-call-plan-v2.tsv`. Verify every frozen file with
`(cd "$EVIDENCE" && sha256sum -c SHA256SUMS)` from the repository root.
