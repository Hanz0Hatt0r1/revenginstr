# Shift `00a3dda0`: exact call root, unresolved callee stores

This replay follows the `STORE@00a3ddbb` to three later loads in `00a3dda0`
across a call to `_memset` at `00a3de30`. The binary is `SHIFT.exe` in program
`nfs-shift:SHIFT.exe`; its SHA-256 is
`eca479aa2d8dbb88bc55709d91ae5c7159ae1b00fc9555d6701000c26de8aee1`. Exports
used Ghidra 12.1.2 DEV with Java 21.

## Captures

`base-capture/` is the fresh read-only export from the saved project.
`parameter-id-capture/` is canonical: Parameter ID was run in a disposable
copy, then the root and three callee flows, CFG/4, memory facts, and caller
arguments were exported from that same copy. The original saved project was
read only.

Parameter ID ran deepest-callee first in this order:
`0090e4b6`, `0090e50d`, `009015b0`, `00a3dda0`. Three passes were needed for a
stable result: the caller return type changed on pass two and did not change
on pass three. The leaf signatures were stable after pass one:

| Function | Recovered signature / change |
| --- | --- |
| `0090e4b6` | `__cdecl fastzero_I(undefined1[16] * param_1, uint param_2)` |
| `0090e50d` | `__cdecl __VEC_memzero(undefined1[16] * param_1, undefined4 param_2, uint param_3)` |
| `009015b0` | `_memset(void *_Dst, int _Val, size_t _Size)`, unchanged |
| `00a3dda0` | `__thiscall FUN_00a3dda0(void * this, int param_1)`; return refined from `undefined4 *` to `void *` on pass two |

The argument-root export proves these exact relationships:

| Call | Callee formal | Caller root |
| --- | --- | --- |
| `00a3dda0@00a3de30` | `009015b0.param0` | `00a3dda0.param0 + 0x98` |
| `009015b0@009015d7` | `0090e50d.param0..2` | matching `009015b0.param0..2 + 0` |
| `0090e50d@0090e53e` | `0090e4b6.param0` | `0090e50d.param0 + 0` |

At the root call, the other arguments are zero and `0x44`. The sidecar has no
offset-root rows for the recursive call in `0090e50d` or
`0090e4b6.param1`.

## Replay result

The root has one parameter-value STORE (`param0+4`, value from `param1`) and
three loads of `param0+4`, yielding three exact field pairs. Its 50 memory
STORE facts all have parameter-rooted constant offsets. The three callee
exports add 13 STORE facts (3 in `009015b0`, 2 in `0090e50d`, 8 in `0090e4b6`);
all 13 locations remain unresolved through `MULTIEQUAL`. The CFG/4 capture has
all four functions.

The call at `00a3de30` is after the root STORE and before all three loads. The
path audit reports `intervening_store_or_call` for all pairs. Direct-call
closure reports one `explicit_memory_write`; `/2` reports three
`possible_aliasing_write` rows, each retaining all 13 unresolved callee STORE
facts and proving zero non-aliasing writes. The exact `+0x98` argument root is
therefore useful but not enough to assign byte offsets to the callee STOREs.
Both dominance replays keep all three pairs at
`possible_intervening_memory_effect`, even though the root STORE dominates
each load. No unique candidate is promoted.

The analyzer replay was run twice from the frozen inputs. Both
`interprocedural-memory-effects.jsonl` outputs were byte-identical to each
other and to the saved output (SHA-256
`cb8263dc974ece07b8b88bc9010a53153b67746469c6a3779109a93a06d74ab4`).

## Reproduce the capture

The saved Ghidra project and original binary are external inputs. Copy the
project before persisting Parameter ID:

```sh
export GHIDRA_HOME=/opt/ghidra
PROJECT_DIR=/home/pes/ghidra_projects
PROJECT_NAME=nfs_shift_vulkan_runtime_20261018
PROGRAM=SHIFT.exe
CAPTURE=docs/evidence/field-store-load-shift-00a3dda0/parameter-id-capture
TEMP_PROJECT_DIR=$(mktemp -d)
cp -a "$PROJECT_DIR/$PROJECT_NAME.gpr" "$PROJECT_DIR/$PROJECT_NAME.rep" "$TEMP_PROJECT_DIR/"

# Parameter ID order is callee before caller. Three passes reached a fixed point.
for pass in 1 2 3; do
  scripts/run_ghidra_parameter_id.sh "$TEMP_PROJECT_DIR" "$PROJECT_NAME" "$PROGRAM" \
    0090e4b6 0090e50d 009015b0 00a3dda0
done

mkdir -p "$CAPTURE/callee-pcode-flow"
for entry in 00a3dda0 009015b0 0090e50d 0090e4b6; do
  if [ "$entry" = 00a3dda0 ]; then
    store="$CAPTURE/parameter-stores.tsv"
    loads="$CAPTURE/parameter-loads.tsv"
    memory="$CAPTURE/memory-store-access.jsonl"
    flow="$CAPTURE/function-pcode-flow.tsv"
  else
    store="$CAPTURE/callee-pcode-flow/$entry-parameter-stores.tsv"
    loads="$CAPTURE/callee-pcode-flow/$entry-parameter-loads.tsv"
    memory="$CAPTURE/callee-pcode-flow/$entry-memory-store-access.jsonl"
    flow="$CAPTURE/callee-pcode-flow/$entry.tsv"
  fi
  scripts/run_ghidra_function_pcode_flow.sh "$TEMP_PROJECT_DIR" "$PROJECT_NAME" "$PROGRAM" \
    "$entry" "$flow"
  scripts/run_ghidra_parameter_store_field.sh "$TEMP_PROJECT_DIR" "$PROJECT_NAME" "$PROGRAM" \
    "$entry" "$store" --load-output "$loads" \
    --memory-access-output "$memory" --program-id nfs-shift:SHIFT.exe
done

scripts/run_ghidra_function_pcode_cfg.sh "$TEMP_PROJECT_DIR" "$PROJECT_NAME" "$PROGRAM" \
  "$CAPTURE/function-pcode-cfg-v4.jsonl" nfs-shift:SHIFT.exe \
  00a3dda0 009015b0 0090e50d 0090e4b6 --indirect-effect-links
scripts/run_ghidra_caller_argument_subtree.sh "$TEMP_PROJECT_DIR" "$PROJECT_NAME" "$PROGRAM" \
  "$CAPTURE/caller-argument-plan-v2.tsv" "$CAPTURE/caller-argument-subtree.tsv" \
  --parameter-root-output "$CAPTURE/caller-argument-roots.tsv" \
  --parameter-offset-root-output "$CAPTURE/caller-argument-offset-roots.tsv"
```

## Reproduce the analyzers

Run from the RevEngInstr repository root. These commands write to a temporary
directory so the committed captures remain unchanged:

```sh
CAPTURE=docs/evidence/field-store-load-shift-00a3dda0/parameter-id-capture
REPLAY=$(mktemp -d)
cat "$CAPTURE/memory-store-access.jsonl" \
  "$CAPTURE"/callee-pcode-flow/*-memory-store-access.jsonl \
  > "$REPLAY/memory-store-access-closure.jsonl"
uv run --project . revenginstr-receiver-field-access-pairs \
  "$CAPTURE/parameter-stores.tsv" "$CAPTURE/parameter-loads.tsv" \
  --program-id nfs-shift:SHIFT.exe \
  --memory-store-access-jsonl "$REPLAY/memory-store-access-closure.jsonl" \
  --output "$REPLAY/field-access-pairs.jsonl"
uv run --project . revenginstr-receiver-field-store-load-audit \
  "$REPLAY/field-access-pairs.jsonl" "$CAPTURE/function-pcode-cfg-v4.jsonl" \
  --output "$REPLAY/path-audit.jsonl"
uv run --project . revenginstr-direct-call-memory-effect-closure \
  "$CAPTURE/function-pcode-flow.tsv" --program-id nfs-shift:SHIFT.exe \
  --callee-flow 009015b0 "$CAPTURE/callee-pcode-flow/009015b0.tsv" \
  --callee-flow 0090e50d "$CAPTURE/callee-pcode-flow/0090e50d.tsv" \
  --callee-flow 0090e4b6 "$CAPTURE/callee-pcode-flow/0090e4b6.tsv" \
  --output "$REPLAY/direct-call-memory-effect-closure.jsonl"
uv run --project . revenginstr-interprocedural-memory-effects \
  "$REPLAY/field-access-pairs.jsonl" "$CAPTURE/function-pcode-cfg-v4.jsonl" \
  "$REPLAY/memory-store-access-closure.jsonl" "$CAPTURE/caller-argument-offset-roots.tsv" \
  --pcode-flow 00a3dda0 "$CAPTURE/function-pcode-flow.tsv" \
  --pcode-flow 009015b0 "$CAPTURE/callee-pcode-flow/009015b0.tsv" \
  --pcode-flow 0090e50d "$CAPTURE/callee-pcode-flow/0090e50d.tsv" \
  --pcode-flow 0090e4b6 "$CAPTURE/callee-pcode-flow/0090e4b6.tsv" \
  --output "$REPLAY/interprocedural-memory-effects.jsonl"
uv run --project . revenginstr-receiver-field-store-load-dominance-audit \
  "$REPLAY/field-access-pairs.jsonl" "$CAPTURE/function-pcode-cfg-v4.jsonl" \
  --memory-store-access-jsonl "$REPLAY/memory-store-access-closure.jsonl" \
  --direct-call-memory-effect-closure-jsonl "$REPLAY/direct-call-memory-effect-closure.jsonl" \
  --output "$REPLAY/dominance-with-call-closure.jsonl"
uv run --project . revenginstr-receiver-field-store-load-dominance-audit \
  "$REPLAY/field-access-pairs.jsonl" "$CAPTURE/function-pcode-cfg-v4.jsonl" \
  --memory-store-access-jsonl "$REPLAY/memory-store-access-closure.jsonl" \
  --interprocedural-memory-effect-jsonl "$REPLAY/interprocedural-memory-effects.jsonl" \
  --output "$REPLAY/dominance-with-interprocedural-effects.jsonl"

for name in field-access-pairs path-audit direct-call-memory-effect-closure \
  interprocedural-memory-effects dominance-with-call-closure \
  dominance-with-interprocedural-effects; do
  cmp "$REPLAY/$name.jsonl" "$CAPTURE/$name.jsonl"
done
```

## Key hashes

| Artifact | SHA-256 |
| --- | --- |
| Root P-code flow | `75e23af69631b893a5eb4643f3b59c0c2a0a959c3d6b7418f620b0cd3e467aa8` |
| Parameter stores | `10dd21c091835a09a640f8fe9a40594d6101fb426298298bdd227e088d405bf0` |
| Parameter loads | `84dbd52286bd9fbc02b7fe2d4bfc8bf49f9c04043af52e068dd0d5c0301dafdc` |
| CFG/4 | `9cf76b2c2bb08d35d6fd88a5e7a03fb81dcf1ff43bfa7dd3db00f1a14a1a9738` |
| Caller argument subtree | `e9491f6cfa32f4a87a4e5018eb21d3f9f8cff1beb41131cfd0ee42d7c8ec5c57` |
| Caller offset roots | `d644c2a8230f0fcf0d2072a880d266cfeb660a9c11c2b86f86b0a04c3ede380d` |
| Memory-store access closure | `02ad8ef30064efaa3636fdb3ed4ae0f23c4bfd0f98fd05b2dee26b34a30c3ae7` |
| Field access pairs | `9711bfe46591f29ac30b8445101a7faf7360451bb979dc343236a63e35fc2110` |
| Path audit | `419ebbb53bb2683bb48f46fd5d0e38ac5e38dc48e3d9aba5323d1bdb33b18496` |
| Direct-call effect closure | `a187f626795dbee77053a7bee4b6f8eccb5a385adaeb45e6aca719d1a268bacf` |
| Interprocedural memory effects/2 | `cb8263dc974ece07b8b88bc9010a53153b67746469c6a3779109a93a06d74ab4` |
| Dominance with direct closure | `31c6fa894d52ef59eb03339a26c6c72ccfb2c5dd57b34c9cdaa4d6ada7bd0c99` |
| Dominance with interprocedural effects | `4b64419d36111a6525c4747bb22d268713c7f196564c3ce12db3e212b15c2f4d` |
