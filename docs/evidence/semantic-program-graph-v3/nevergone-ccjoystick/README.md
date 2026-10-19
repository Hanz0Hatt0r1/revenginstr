# Nevergone CCJoyStick layout in SemanticProgramGraph/3

This replay joins the existing Nevergone player-facing Function Effect IR with
its independently reviewed `CCJoyStick` layout hypothesis. The layout source
was produced with program id `nevergone:libcocos2dcpp.so`; this replay copy uses
the exact program id already present in the Function Effect IR,
`nevergone-1.0.9-armv7-libcocos2dcpp`. Both inputs refer to the same pinned
Nevergone 1.0.9 ARMv7 library SHA-256 recorded in `manifest.json`. The builder
requires exact program-id equality and does not infer or repair identities.

The resulting graph has one layout type, 13 layout-field nodes, and 24 total
edges. It retains the reviewed exact size of 340 bytes, the 337-byte observed
lower bound, candidate field types and source evidence. It assigns no field
confidence and does not infer that function-local field observations elsewhere
in the graph refer to this object. `+0x104` remains a reviewed pointer
candidate to `cocos2d::CCSprite`.

## Reproduce

From the repository root:

```sh
PYTHONPATH=src python -m revenginstr.semantic_program_graph \
  docs/evidence/semantic-program-graph-evaluation/nevergone-player-horizontal-facing/nevergone-facing-effects.jsonl \
  --type-layout-hypotheses docs/evidence/semantic-program-graph-v3/nevergone-ccjoystick/type-layout-hypothesis.jsonl \
  --output /tmp/nevergone-ccjoystick-graph-v3.jsonl

PYTHONPATH=src python -m revenginstr.semantic_program_query \
  /tmp/nevergone-ccjoystick-graph-v3.jsonl \
  --view exploratory \
  --kind layout_field \
  --type-id nevergone:opaque-object-002a6584 \
  --field-offset 0x104 \
  --output /tmp/nevergone-ccjoystick-field-104.jsonl
```

The checked-in graph and query outputs are deterministic replay snapshots. The
manifest pins the input and output artifact hashes.
