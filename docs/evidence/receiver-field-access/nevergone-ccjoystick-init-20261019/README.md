# Nevergone `CCJoyStick::init` field access replay

This is a consumer-owned replay of the generic field store/load audit for
`CCJoyStick::init` at entry `002a6584`. The original binary is not included.

## Source identity

- Original Android package: `com.hippiegame.nevergone`
- APK SHA-256 pulled read-only from the attached device: `97296efc9d32fdd46bdf2dba475aeb13adb4cc6d2957ddf02da7a5d9c56e9508`
- `lib/armeabi-v7a/libcocos2dcpp.so` SHA-256: `94b1ef6a9469e261183ac08199c5b0eb65c0c40b81918ca097bd32920828eb5e`
- Captured Ghidra mode/version: `12.1.2_DEV`, read-only, no analysis
- Captured program id: `nevergone:libcocos2dcpp.so`
- The input exports were previously captured from the analyzed Ghidra project and are copied byte-for-byte from the Nevergone consumer repository. The binary and Ghidra project remain outside this repository.

REA verified the APK member hash against the captured ELF identity. A fresh
REA function-analysis request exceeded its 330-second Ghidra startup deadline,
so this replay validates the existing exported evidence and analyzer behavior;
it does not claim a fresh decompilation.

## Replay result

The input contains six parameter-rooted stores, nine parameter-rooted loads,
two exact parameter/offset pair graphs, one CFG/3 row with eight blocks, and
twelve parameter-rooted memory-store facts. The current dominance audit
reproduces the frozen `/2` result byte-for-byte (`0bf48e0f06f7afbf918044718e12b3b72b47a83c316ac6aeb9547d1d9da5e911`): two rows, zero mismatches, and zero unique store candidates.

| Field | Paired access | Audit status | Structural reading |
|---|---|---|---|
| `0x119` | store `002a65a8` / time 49 → load `002a6648` / time 168 | `possible_intervening_memory_effect` | The store dominates the load, but a represented memory effect remains on the path through blocks `[2]`. |
| `0x11a` | store `002a65b8` / time 60 → load `002a6658` / time 209 | `possible_intervening_memory_effect` | The store dominates the load, but a represented memory effect remains on the path through blocks `[2, 3]`. |

These are conservative structural candidates. The audit cannot determine
whether an intervening store aliases the paired field, which store reaches a
load, or what either field means at runtime. The offsets and widths are byte
facts, not semantic labels.

## Effect IR and graph projection

The same captured TSV inputs also replay through the higher-level analyzer:

- FunctionEffectIR/1 emits 15 parameter-rooted read/write facts for
  `CCJoyStick::init`.
- SemanticProgramGraph/1 emits 26 nodes and 31 edges.
- The exploratory query selects the two fields at `0x119` and `0x11a`, with
  four read/write edges and their four operation nodes as context.

The checked-in Function Effect IR, graph, and query files are frozen outputs
from these inputs. They are projection fixtures, not independent semantic
gold labels. The benchmark reruns all three stages and validates each output
schema. This replay keeps fields scoped to function entry, formal parameter,
and offset; it does not connect them to a type/layout hypothesis or infer the
fields' runtime meaning.

The benchmark also queries the separately reviewed Nevergone layout graph at
the same offsets. It returns two `review` layout fields, each with a one-byte
boolean candidate and read/write provenance. That graph uses the opaque
program id `nevergone-1.0.9-armv7-libcocos2dcpp`; the field TSV capture uses
`nevergone:libcocos2dcpp.so`. Their manifests pin the same exact program SHA,
but the query preserves the separate graph identities and creates no edge
between them.

## Reproduce

From the repository root, run:

```sh
uv run --project . revenginstr-benchmark \
  docs/evidence/receiver-field-access/nevergone-ccjoystick-init-20261019/benchmark-manifest.json \
  --mode smoke \
  --output /tmp/nevergone-ccjoystick-init-replay-summary.json
```

The benchmark manifest pins the schemas, stage inputs, and expected audit
output. The accompanying artifact manifest also pins the checked-in
FunctionEffectIR, graph, and query projection files. The benchmark replays the
CFG audit, builds FunctionEffectIR/1 and SemanticProgramGraph/1, then queries
both the paired fields and the separately reviewed layout graph. Its audit
comparison covers status, both access identities, CFG witnesses,
memory-effect results, claim scope, and provenance.
The generated files under `frozen-replay/` are not checked in; remove that
directory before repeating the command because benchmark output paths are
deliberately protected from accidental overwrite.

The captured parameter TSVs and source-tool revision describe the historical
export. The replay itself was run with RevEngInstr commit
`0b4deff` (`Replay runtime value-flow results into decision ledger`).

This remains the behavior of the frozen benchmark described above. A separate
SemanticProgramGraph/3 replay rebuilds the FunctionEffectIR with the layout's
exact program id and uses the reviewer-supplied member map to connect nine
matching parameter-rooted field nodes to the reviewed type. It retains null
confidence and review provenance; see the
[`field-to-layout replay`](../../semantic-program-graph-v3/nevergone-ccjoystick-init-layout-join-20261020/README.md).
