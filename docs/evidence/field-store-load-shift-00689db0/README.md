# Shift `00689db0`: memory-only stores across calls

This replay follows the two calls on the `STORE@00689e0a` to
`LOAD@00689e49` path. It keeps the field destination exact while treating the
store value and any call effects conservatively. The binary is `SHIFT.exe` in
program `nfs-shift:SHIFT.exe`; its SHA-256 is
`eca479aa2d8dbb88bc55709d91ae5c7159ae1b00fc9555d6701000c26de8aee1`.
Exports used Ghidra 12.1.2 DEV with Java 21.

## Captures

`base-capture/` is the first fresh, read-only export from the saved project.
Its direct-call closure already showed explicit writes in `0067db80` and
`004f5eb0`, with a nested write in `0042eff7`. The saved function signatures
did not expose call arguments, so its caller-root sidecars are empty.

`parameter-id-capture/` is the canonical replay. Parameter ID was applied to
a disposable copy of the saved Ghidra project, then the root and all three
callee flows, CFG/4 records, memory facts, and caller arguments were exported
from that same copy. The original saved project was only read. Two
callee-before-caller Parameter ID passes reached a fixed point:

| Function | First pass signature | Second pass |
| --- | --- | --- |
| `0042eff7` | `__stdcall FUN_0042eff7(void)` | unchanged |
| `0067db80` | `__fastcall FUN_0067db80(int * param_1, undefined4 * param_2)` | unchanged |
| `004f5eb0` | `__fastcall FUN_004f5eb0(int * param_1, int * param_2)` | unchanged |
| `00689db0` | `__thiscall FUN_00689db0(void * this, int * param_1, int * param_2, int * param_3, int * param_4)` | unchanged |

The caller-argument subtree identifies the second actual argument at
`00689e15` as stack-pointer register `00000010` minus `0x18` and the second
argument at `00689e24` as that register minus `0x10`. Neither is rooted in a
caller formal, so both offset-root sidecars correctly contain only their
headers.
`0042eff7` remains a `void` function; its call has no explicit argument and
its STORE destination is unresolved. No caller-to-callee alias proof is
available from these facts.

## Replay result

The parameter-ID capture has 21 parameter loads, no parameter-value STORE
rows, 28 root memory STORE facts (8 parameter-rooted), and 20 exact field
store/load pairs. The CFG/4 export includes four functions and skips none.

For the witness pair `STORE@00689e0a` (time 240, `param1+0`) to
`LOAD@00689e49` (time 301), calls `00689e15` (time 257) and `00689e24`
(time 268) intervene. The first callee writes through its second parameter;
the second writes through its second parameter and reaches the nested
unresolved STORE in `0042eff7`.

The path audit reports 16 `intervening_store_or_call` and 4 `no_cfg_path`
rows. Both the direct-call closure and `/2` interprocedural audit preserve the
same `/7` result: 16 `store_not_dominating_load`, 4
`possible_intervening_memory_effect`, and no unique candidates. Across the 20
pairs, `/2` emits 40 `possible_aliasing_write`, 20 `unknown_effect`, and 60
`missing_callee_flow` rows. It proves no disjoint write. Repeating the `/2`
command with the frozen capture produced byte-identical JSONL.

## Reproduce

Run from the RevEngInstr repository root. The saved Ghidra project and the
original binary are external inputs. Copy the project before persisting
Parameter ID:

```sh
export GHIDRA_HOME=/opt/ghidra
PROJECT_DIR=/home/pes/ghidra_projects
PROJECT_NAME=nfs_shift_vulkan_runtime_20261018
PROGRAM=SHIFT.exe
CAPTURE=docs/evidence/field-store-load-shift-00689db0/parameter-id-capture
TEMP_PROJECT_DIR=$(mktemp -d)
cp -a "$PROJECT_DIR/$PROJECT_NAME.gpr" "$PROJECT_DIR/$PROJECT_NAME.rep" "$TEMP_PROJECT_DIR/"

# Apply Parameter ID in callee-before-caller order; the second pass is stable.
scripts/run_ghidra_parameter_id.sh "$TEMP_PROJECT_DIR" "$PROJECT_NAME" "$PROGRAM" \
  0042eff7 0067db80 004f5eb0 00689db0
scripts/run_ghidra_parameter_id.sh "$TEMP_PROJECT_DIR" "$PROJECT_NAME" "$PROGRAM" \
  0042eff7 0067db80 004f5eb0 00689db0

# Export P-code flows and per-function field/memory facts from this same copy.
for entry in 00689db0 0067db80 004f5eb0 0042eff7; do
  store="$CAPTURE/callee-pcode-flow/$entry-parameter-stores.tsv"
  loads="$CAPTURE/callee-pcode-flow/$entry-parameter-loads.tsv"
  memory="$CAPTURE/callee-pcode-flow/$entry-memory-store-access.jsonl"
  flow="$CAPTURE/callee-pcode-flow/$entry.tsv"
  if [ "$entry" = 00689db0 ]; then
    store="$CAPTURE/parameter-stores.tsv"
    loads="$CAPTURE/parameter-loads.tsv"
    memory="$CAPTURE/memory-store-access.jsonl"
    flow="$CAPTURE/function-pcode-flow.tsv"
  fi
  scripts/run_ghidra_function_pcode_flow.sh "$TEMP_PROJECT_DIR" "$PROJECT_NAME" "$PROGRAM" \
    "$entry" "$flow"
  scripts/run_ghidra_parameter_store_field.sh "$TEMP_PROJECT_DIR" "$PROJECT_NAME" "$PROGRAM" \
    "$entry" "$store" --load-output "$loads" \
    --memory-access-output "$memory" --program-id nfs-shift:SHIFT.exe
done
scripts/run_ghidra_function_pcode_cfg.sh "$TEMP_PROJECT_DIR" "$PROJECT_NAME" "$PROGRAM" \
  "$CAPTURE/function-pcode-cfg-v4.jsonl" nfs-shift:SHIFT.exe \
  00689db0 0067db80 004f5eb0 0042eff7 --indirect-effect-links

# Export exact caller arguments for the three observed callee parameters.
scripts/run_ghidra_caller_argument_subtree.sh "$TEMP_PROJECT_DIR" "$PROJECT_NAME" "$PROGRAM" \
  "$CAPTURE/caller-argument-plan-v2.tsv" "$CAPTURE/caller-argument-subtree.tsv" \
  --parameter-root-output "$CAPTURE/caller-argument-roots.tsv" \
  --parameter-offset-root-output "$CAPTURE/caller-argument-offset-roots.tsv"

# Replay field pairs, path audit, direct-call closure, /2 effects, and /7 dominance.
cat "$CAPTURE/memory-store-access.jsonl" \
  "$CAPTURE"/callee-pcode-flow/*-memory-store-access.jsonl \
  > "$CAPTURE/memory-store-access-closure.jsonl"
uv run --project . revenginstr-receiver-field-access-pairs \
  "$CAPTURE/parameter-stores.tsv" "$CAPTURE/parameter-loads.tsv" \
  --program-id nfs-shift:SHIFT.exe \
  --memory-store-access-jsonl "$CAPTURE/memory-store-access-closure.jsonl" \
  --output "$CAPTURE/field-access-pairs.jsonl"
uv run --project . revenginstr-receiver-field-store-load-audit \
  "$CAPTURE/field-access-pairs.jsonl" "$CAPTURE/function-pcode-cfg-v4.jsonl" \
  --output "$CAPTURE/path-audit.jsonl"
uv run --project . revenginstr-direct-call-memory-effect-closure \
  "$CAPTURE/function-pcode-flow.tsv" --program-id nfs-shift:SHIFT.exe \
  --callee-flow 0067db80 "$CAPTURE/callee-pcode-flow/0067db80.tsv" \
  --callee-flow 004f5eb0 "$CAPTURE/callee-pcode-flow/004f5eb0.tsv" \
  --callee-flow 0042eff7 "$CAPTURE/callee-pcode-flow/0042eff7.tsv" \
  --output "$CAPTURE/direct-call-memory-effect-closure.jsonl"
uv run --project . revenginstr-interprocedural-memory-effects \
  "$CAPTURE/field-access-pairs.jsonl" "$CAPTURE/function-pcode-cfg-v4.jsonl" \
  "$CAPTURE/memory-store-access-closure.jsonl" "$CAPTURE/caller-argument-offset-roots.tsv" \
  --pcode-flow 00689db0 "$CAPTURE/function-pcode-flow.tsv" \
  --pcode-flow 0067db80 "$CAPTURE/callee-pcode-flow/0067db80.tsv" \
  --pcode-flow 004f5eb0 "$CAPTURE/callee-pcode-flow/004f5eb0.tsv" \
  --pcode-flow 0042eff7 "$CAPTURE/callee-pcode-flow/0042eff7.tsv" \
  --output "$CAPTURE/interprocedural-memory-effects.jsonl"
uv run --project . revenginstr-receiver-field-store-load-dominance-audit \
  "$CAPTURE/field-access-pairs.jsonl" "$CAPTURE/function-pcode-cfg-v4.jsonl" \
  --memory-store-access-jsonl "$CAPTURE/memory-store-access-closure.jsonl" \
  --direct-call-memory-effect-closure-jsonl "$CAPTURE/direct-call-memory-effect-closure.jsonl" \
  --output "$CAPTURE/dominance-with-call-closure.jsonl"
uv run --project . revenginstr-receiver-field-store-load-dominance-audit \
  "$CAPTURE/field-access-pairs.jsonl" "$CAPTURE/function-pcode-cfg-v4.jsonl" \
  --memory-store-access-jsonl "$CAPTURE/memory-store-access-closure.jsonl" \
  --interprocedural-memory-effect-jsonl "$CAPTURE/interprocedural-memory-effects.jsonl" \
  --output "$CAPTURE/dominance-with-interprocedural-effects.jsonl"
```

## Key hashes

| Artifact | SHA-256 |
| --- | --- |
| Parameter-ID root P-code flow | `a2c2297db6625abefb58adf157e05a3fb04cf0b7f0136e46bda0b727a3aec59e` |
| Parameter-ID CFG/4 | `73307a5bf3dc330ccd4472d02992280fc50bdbe902ccc6a1897f38632c6e08f8` |
| Parameter-ID caller argument subtree | `8ae901c66ae5bcb971549cae3aee894db35cc4f75551c0226a7c7c1f24e7e812` |
| Caller offset roots | `84476b9f55baf27f9d798b9d2cb6915becc88b0bcf68266cd9f8bc077a2c373a` |
| Memory-store access closure | `2f3245d1154fad72fc904d4e3f349988050a72375803a98436106daae3003e04` |
| Field access pairs | `20b6a00e8664c3c82f492b6b9e682bae237be6f49d0c67968500bd0969afb1f4` |
| Path audit | `485593725460d24dbdcc8c1211d53e23ed80b5ba8cfb37e21f0cc446573649b7` |
| Direct-call effect closure | `df1a6442efa51964f3c8b369f6712532703879516e9b3cd98db63fa06e2ab798` |
| Interprocedural memory effects/2 | `4ac7703a7255648c55c2b4d917d00107ace299f91e7b4ff7df7f2ed8143981c2` |
| Dominance with direct closure | `f8f181b6abdf28e4bf58bc8046e7a40e73cc80d35ee92aa520b0530609bc5371` |
| Dominance with interprocedural effects | `b987d93fd406ea980124d69d40f5cceff5b65b3b03edd617d090a7acb7c14579` |
