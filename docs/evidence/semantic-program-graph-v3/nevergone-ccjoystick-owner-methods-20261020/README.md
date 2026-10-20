# Nevergone `CCJoyStick` owner-method field replay

This replay extends the `init` and `updateTouchPoint` sample to six additional
methods whose separately exported Ghidra prototypes identify parameter 0 as a
`CCJoyStick *`: the destructor at `0x002a5e08`, constructor at `0x002a5ea0`,
`onTouchMoved` at `0x002a6048`, `resetJoyStick` at `0x002a643c`,
`setHitAreaWithRect` at `0x002a6570`, and `getPower` at `0x002a66c6`. The stored
signatures are marked `ANALYSIS`; they corroborate the method-owner join but are
not treated as truth.

The read-only exports add four parameter-rooted loads and thirteen exact
parameter-rooted STORE locations. Together with the earlier two-method replay,
the input has 25 parameter loads, six parameter-to-parameter stores, 27
parameter-rooted memory stores, and 302 retained P-code rows. All six new
function-flow acquisitions completed. The layout hypothesis grows from 13 to
19 observed offsets by adding `0xe0`, `0xe4`, `0xe8`, `0x12c`, `0x138`, and
`0x14c`; its 337-byte observed extent and 340-byte allocation size do not
change. The other added offsets (`0xe0`, `0xe4`, `0xe8`, `0x12c`, and `0x14c`)
remain untyped.

The graph has 168 nodes, 240 edges, and 36 type-to-field joins across the eight
methods. The scoped gold uses the separate method prototypes, the rebuilt
layout hypothesis, and raw field-access records. It contains no
`TypeLayoutMemberMap/1` evidence. All 36 joins match in the exploratory view
with complete provenance. No edge is accepted because confidence remains
null. This is a narrow cross-artifact owner-type check; it does not establish
field meanings, direct-versus-inherited ownership, store-to-load flow, or
runtime behavior. M10.5 remains open.

## Manually reviewed type candidates

The access traces support four conservative type candidates. The byte at
`+0x138` is cleared by `resetJoyStick` and gates the `onTouchMoved` path; the
byte at `+0x150` also gates that path. Both are recorded as boolean candidates.
The values at `+0x13c` and `+0x140` are stored from `FLOAT_DIV` and
`FLOAT2FLOAT` results in `updateTouchPoint`; `getPower` returns the value loaded
from `+0x13c`. They are recorded as 32-bit floating-point candidates. The
review rows pin these interpretations to exact P-code or memory-access records.
No member names, accepted types, or runtime behavior are inferred.

## Reproduce the read-only exports

Export the exact owner prototypes:

```sh
GHIDRA_HOME=/opt/ghidra \
  scripts/run_ghidra_function_prototypes.sh \
  /home/pes/ghidra_projects nevergone_title_enemy libcocos2dcpp.so \
  docs/evidence/semantic-program-graph-v3/nevergone-ccjoystick-owner-methods-20261020/method-plan.tsv \
  /tmp/ccjoystick-owner-method-prototypes.jsonl
```

The prototype, parameter-field, and P-code exports were rerun from the local
Ghidra 12.1.2 project with Java 21. Their retained raw outputs matched the
checked-in exports byte for byte.

Export field accesses for the six additional methods:

```sh
GHIDRA_HOME=/opt/ghidra \
  scripts/run_ghidra_parameter_store_field.sh \
  /home/pes/ghidra_projects nevergone_title_enemy libcocos2dcpp.so \
  002a5e08 /tmp/ccjoystick-owner-method-stores.tsv \
  --function-entry 002a5ea0 \
  --function-entry 002a6048 \
  --function-entry 002a643c \
  --function-entry 002a6570 \
  --function-entry 002a66c6 \
  --load-output /tmp/ccjoystick-owner-method-loads.tsv \
  --memory-access-output /tmp/ccjoystick-owner-method-memory-stores.jsonl \
  --program-id 'nevergone:libcocos2dcpp.so'
```

Export P-code flow and acquisition status for those same six entries:

```sh
GHIDRA_HOME=/opt/ghidra \
  scripts/run_ghidra_pcode_flow_batch.sh \
  /home/pes/ghidra_projects nevergone_title_enemy libcocos2dcpp.so \
  docs/evidence/semantic-program-graph-v3/nevergone-ccjoystick-owner-methods-20261020/function-entries.txt \
  /tmp/ccjoystick-owner-method-pcode.tsv \
  /tmp/ccjoystick-owner-method-callind.jsonl \
  /tmp/ccjoystick-owner-method-acquisition.jsonl 20 600
```

The checked-in replay test verifies the combined inputs, rebuilds Effect IR,
layout, graph, query, and evaluation, and checks every gold reference against
its hash-pinned source record:

```sh
pytest -q tests/test_semantic_program_graph_layout.py \
  -k owner_methods_replay_is_reproducible
```

The manifest pins the source exports, prior Nevergone inputs, type-review
candidates, schemas, derived artifacts, and this README.
