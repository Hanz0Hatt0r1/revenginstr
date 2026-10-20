# Nevergone `CCJoyStick` touch-pipeline replay

This replay joins two exact callback-to-helper paths with the existing
eight-method owner graph and the three manually reviewed touch helpers. It is
pinned to the Nevergone 1.0.9 ARM32 ELF SHA-256
`94b1ef6a9469e261183ac08199c5b0eb65c0c40b81918ca097bd32920828eb5e`.

The callback P-code was exported from the existing Ghidra 12.1.2 project in
read-only, no-analysis mode with Java 21. The checked-in
[`function-entries.txt`](function-entries.txt), P-code, `CALLIND` evidence and
acquisition receipt retain the exact export for `CCJoyStick::ccTouchBegan`
(`0x002a6300`) and `CCJoyStick::ccTouchEnded` (`0x002a63ec`). Both functions
completed; the export contains 56 P-code rows. The original Ghidra project was
not modified.

## Replay result

The deterministic builder composes 13 function bodies: the eight existing
owner methods, the three touch helpers, and the two callback methods. The graph
contains 276 nodes and 407 edges. Its 53 parameter-field-to-type joins use the
owner and helper `TypeLayoutMemberMap/1` rows. Those joins retain human-review
provenance and null confidence; none is accepted as a semantic fact.

Three exact-only path queries recover these direct calls:

| Caller | Call site | Callee |
| --- | ---: | --- |
| `CCJoyStick::ccTouchBegan` (`0x002a6300`) | `0x002a6308` | `CCJoyStick::containsTouchLocation` (`0x002a60c8`) |
| `CCJoyStick::ccTouchBegan` (`0x002a6300`) | `0x002a6362` | `CCJoyStick::onTouchBegan` (`0x002a6284`) |
| `CCJoyStick::ccTouchEnded` (`0x002a63ec`) | `0x002a642c` | `CCJoyStick::onTouchEnd` (`0x002a63a8`) |

The hit-area query selects reads of `+0x11c`, `+0x120`, `+0x124`, `+0x128`,
and `+0x12c` in `containsTouchLocation`, plus the `+0x12c` write in
`setHitAreaWithRect`. The separate receiver review documents why root parameter
0 is the `CCJoyStick` object for the three helpers. It also traces the first
four offsets to the assigned `CCRect` components and `+0x12c` to the distance
threshold. The graph keeps byte offsets and reviewer provenance; it assigns no
field names.

The path queries retain unresolved call frontiers: eight sites in the
`ccTouchBegan` reachable region and two in the `ccTouchEnded` region. They stay
`CALLIND` barriers with no synthesized targets. This is a static graph replay;
it does not prove branch feasibility, touch behavior at runtime, or ownership
of the object. The exploratory field query does not accept the reviewed type
candidates. The broader M10.5 accuracy and two-subsystem criteria remain open.

## Reproduce

Re-export the two callbacks to temporary files:

```sh
GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_pcode_flow_batch.sh \
  /home/pes/ghidra_projects nevergone_title_enemy libcocos2dcpp.so \
  docs/evidence/semantic-program-graph-v3/nevergone-ccjoystick-touch-pipeline-20261020/function-entries.txt \
  /tmp/ccjoystick-touch-callbacks.tsv \
  /tmp/ccjoystick-touch-callback-callind.jsonl \
  /tmp/ccjoystick-touch-callback-acquisition.jsonl 2 600
```

Compare the temporary outputs to the pinned callback artifacts, then rebuild
the combined Effect IR, graph, path queries and field query:

```sh
PYTHONPATH=src python \
  docs/evidence/semantic-program-graph-v3/nevergone-ccjoystick-touch-pipeline-20261020/rebuild.py \
  --output-dir /tmp/nevergone-ccjoystick-touch-pipeline
```

The rebuild composes the pinned callback export with the owner-method and
touch-helper evidence in the neighboring replay directories. The checked-in
[`replay-manifest.json`](replay-manifest.json) pins those inputs, the derived
artifacts, the replayer, and this README.
