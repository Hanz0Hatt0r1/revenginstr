# Nevergone `CCJoyStick` method-pair field graph

This replay combines structural effects from `CCJoyStick::init` at `0x002a6584`
and `CCJoyStick::updateTouchPoint` at `0x002a5f00`. Both use program id
`nevergone:libcocos2dcpp.so` and executable SHA-256
`94b1ef6a9469e261183ac08199c5b0eb65c0c40b81918ca097bd32920828eb5e`.

The `updateTouchPoint` export contains 12 parameter-rooted field loads at
`0x104`, `0x108`, `0x110`, `0x114`, and `0x140`. Its memory-store sidecar
contains two exact parameter-rooted STORE locations at `0x13c` and `0x140`,
each four bytes wide. The new Effect IR projection retains those writes as
structural facts and leaves `source_parameter_index` null because the exporter
does not identify their value source.

A separate 176-row `GhidraFunctionPcodeFlow/1` export cross-checks the 12 LOAD
operation keys and widths and both STORE keys, pointer tokens, and widths. For
each STORE, the retained `CAST` points to the retained `PTRADD`; its constant
offset and scale reproduce the memory sidecar's byte offset. This is a
cross-export consistency check from the same analyzed Ghidra program, not an
independent semantic gold set.

The member map manually associates root parameter 0 of each exact function
entry with the same opaque CCJoyStick type record, based on the Ghidra method
owner identity. The mapping is retained as `human_review` evidence. The graph
has 61 nodes, 89 edges, and 15 type-to-field joins. The selected-offset query
returns 10 method-specific field nodes and the shared type as context; all
derived links keep null confidence. These artifacts do not assign field
meanings, establish runtime aliasing, or claim that any store supplies a later
load.

An additional read-only `GhidraFunctionPrototype/1` export records parameter 0
of both methods as a pointer to `CCJoyStick`. Ghidra labels these signatures
`ANALYSIS`, so the snapshot is corroborating evidence rather than truth. A
scoped, manually adjudicated `has_field` gold is built from the separate
prototype rows, the reviewed type-layout row, and the underlying field-access
rows; it does not cite the member map. The exploratory evaluation matches all
15 scoped joins (precision and recall 1.0, complete provenance). It accepts no
edges: confidence remains null and the relation is not calibrated. This is a
narrow cross-artifact owner-type check, not a general field-accuracy result.

The REA MCP Ghidra provider reported `cleanup_incomplete` for an old analysis
session, so this replay was exported with the repository's standard Ghidra
parameter-store-field tool in `-readOnly -noanalysis` mode. The checked-in
inputs are the exact exporter outputs; no Ghidra analysis was run or modified
for this replay.

Regenerate `update-touchpoint-effects.jsonl` with:

```sh
revenginstr-effect-ir \
  --program-id 'nevergone:libcocos2dcpp.so' \
  --parameter-loads docs/evidence/semantic-program-graph-v3/nevergone-ccjoystick-method-pair-20261020/update-touchpoint-loads.tsv \
  --memory-store-access docs/evidence/semantic-program-graph-v3/nevergone-ccjoystick-method-pair-20261020/update-touchpoint-memory-stores.jsonl \
  --output docs/evidence/semantic-program-graph-v3/nevergone-ccjoystick-method-pair-20261020/update-touchpoint-effects.jsonl
```

The raw P-code cross-check comes from the independent function-flow exporter:

```sh
GHIDRA_HOME=/opt/ghidra \
  scripts/run_ghidra_function_pcode_flow.sh \
  /home/pes/ghidra_projects nevergone_title_enemy libcocos2dcpp.so \
  002a5f00 /tmp/update-touchpoint-pcode-flow.tsv
```

The replay test checks the operation and pointer-expression agreement against
the pinned `update-touchpoint-pcode-flow.tsv` artifact.

Regenerate the exact stored signature snapshot with:

```sh
GHIDRA_HOME=/opt/ghidra \
  scripts/run_ghidra_function_prototypes.sh \
  /home/pes/ghidra_projects nevergone_title_enemy libcocos2dcpp.so \
  docs/evidence/semantic-program-graph-v3/nevergone-ccjoystick-method-pair-20261020/function-prototype-plan.tsv \
  /tmp/ccjoystick-function-prototypes.jsonl
```

The checked-in gold is adjudicated from those prototype rows plus the raw field
evidence and layout hypothesis. Its replay test verifies that every cited
artifact hash and record ordinal resolves and that the gold contains no
member-map evidence.

The replay test rebuilds the Effect IR, combined function artifact, graph, and
query and checks each result byte-for-byte against its pinned output:

```sh
pytest -q tests/test_semantic_program_graph_layout.py -k method_pair
```

The manifest pins the source exports, the manually reviewed member map,
intermediate and final outputs, schemas, and this README.
