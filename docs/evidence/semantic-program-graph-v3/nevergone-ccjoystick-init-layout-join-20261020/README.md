# Nevergone `CCJoyStick::init` field-to-layout graph

This replay joins the captured `CCJoyStick::init` field effects to the reviewed
`CCJoyStick` layout through the exact `TypeLayoutMemberMap/1` row. Both inputs
use program id `nevergone:libcocos2dcpp.so` and pin the same executable SHA-256:
`94b1ef6a9469e261183ac08199c5b0eb65c0c40b81918ca097bd32920828eb5e`.

The graph contains 40 nodes and 54 edges. Nine parameter-rooted field nodes
join to the mapped type through `has_field`; each edge cites the member-map
record, the type-layout row, and the supporting field effect. The query for
`0x119` and `0x11a` returns both field access nodes and the owning type as
context. The links preserve the review status and confidence remains null.
They do not assign runtime meaning to either offset or prove a store-to-load
value flow.

Rebuild the Effect IR from the retained P-code exports, then build and query the
graph:

```sh
revenginstr-effect-ir \
  --program-id 'nevergone:libcocos2dcpp.so' \
  --parameter-stores docs/evidence/receiver-field-access/nevergone-ccjoystick-init-20261019/parameter-stores.tsv \
  --parameter-loads docs/evidence/receiver-field-access/nevergone-ccjoystick-init-20261019/parameter-loads.tsv \
  --output /tmp/nevergone-ccjoystick-init-effects.jsonl

revenginstr-semantic-program-graph \
  /tmp/nevergone-ccjoystick-init-effects.jsonl \
  --type-layout-hypotheses docs/evidence/type-layout-review/nevergone-ccjoystick-20261019/type-layout-hypothesis.jsonl \
  --type-layout-member-maps docs/evidence/type-layout-review/nevergone-ccjoystick-20261019/member-map.jsonl \
  --output /tmp/nevergone-ccjoystick-init-layout-graph.jsonl

revenginstr-semantic-program-query \
  /tmp/nevergone-ccjoystick-init-layout-graph.jsonl \
  --view exploratory \
  --kind field \
  --function-entry 002a6584 \
  --relation has_field \
  --field-offset 0x119 \
  --field-offset 0x11a \
  --output /tmp/nevergone-ccjoystick-init-layout-query.jsonl
```

The checked-in graph and query are deterministic outputs. The replay manifest
pins both inputs, outputs, schemas, and this README.
