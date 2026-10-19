# Nevergone player-facing call graph replay

This replay evaluates the consumer-owned gold subgraph in
[Nevergone PR #734](https://github.com/Hanz0Hatt0r1/nevergone-recomp/pull/734)
at commit [`e1be0b2d759b41991cbaa787dd4dbc9b2423c866`](https://github.com/Hanz0Hatt0r1/nevergone-recomp/commit/e1be0b2d759b41991cbaa787dd4dbc9b2423c866).
The gold covers all three direct calls in the captured
`MEPlayer::setControlsState` and `MeActionsSystem::filpAction` functions.
Its scope declares only `calls` complete.

The source P-code rows and consumer recovery note are pinned in that gold
artifact. The note describes the same shipped binary as the P-code export;
this is a consumer-adjudicated interpretation, not independent binary or
runtime corroboration. It does not validate joystick behavior, field meaning,
runtime execution, or accepted-edge confidence.

## Replay result

| Metric | Result |
| --- | ---: |
| Expected calls | 3 |
| Matched calls | 3 |
| Candidate precision / recall | 1.0 / 1.0 |
| Unsupported edge rate | 0% |
| Provenance completeness | 100% |
| Accepted edges / accepted-edge precision | 0 / `null` |

The graph is `program:6c909c5b932abf2c3a09d25c6ec072be8ab047bee480caf35a68dcb784ce4dcb`
for program `nevergone-1.0.9-armv7-libcocos2dcpp`.

| Artifact | SHA-256 |
| --- | --- |
| Function Effect IR | `5d6c089cbbae5e07ea50b06a84481e3af1f45a176986fa481aed9edc82d0158e` |
| Semantic Program Graph | `b2c64e397bd1e95d5f195b10dfaa2d3254a455377fdac53db9d2c2a6c08f37e5` |
| Evaluation result | `fa480bc65b9188a9e4a1730995187abc30015cf1a15eab70821a6ee5b68c8ce0` |
| Consumer gold subgraph | `ee5cb2c3a3880d3a3da9098c47a5e589d52e0d6137c6297cfff2f8197100d5ec` |

The retained [Function Effect IR](nevergone-facing-effects.jsonl),
[Semantic Program Graph](nevergone-facing-graph.jsonl), and
[evaluation result](nevergone-facing-evaluation.json) preserve the replay
outputs. Rebuild from the RevEngInstr repository root with local checkouts of
both repositories:

```sh
uv run --project . revenginstr-effect-ir \
  --program-id nevergone-1.0.9-armv7-libcocos2dcpp \
  --pcode-flow /path/to/nevergone-recomp/docs/evidence/player-horizontal-facing-pcode.tsv \
  --output /tmp/nevergone-facing-effects.jsonl
uv run --project . revenginstr-semantic-program-graph \
  /tmp/nevergone-facing-effects.jsonl \
  --output /tmp/nevergone-facing-graph.jsonl
uv run --project . revenginstr-semantic-program-graph-evaluate \
  /tmp/nevergone-facing-graph.jsonl \
  /path/to/nevergone-recomp/docs/evidence/semantic-program-graph-gold/player-horizontal-facing/gold-subgraphs.jsonl \
  --view exact-only \
  --output /tmp/nevergone-facing-evaluation.json
```
