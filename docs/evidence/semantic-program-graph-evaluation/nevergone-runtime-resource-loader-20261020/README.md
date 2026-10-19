# Nevergone runtime resource-loader call graph replay

This replay checks the 36 direct-call edges emitted for the two functions found in the real startup capture against Ghidra instruction-level references from a separate exporter. `GameLevels::LoadGameLevels` contributes 9 direct calls; `cocos2d::CCFileUtilsAndroid::getFileData` contributes 27. The instructions export and the graph are pinned to Nevergone 1.0.9 ARMv7 library SHA-256 `94b1ef6a9469e261183ac08199c5b0eb65c0c40b81918ca097bd32920828eb5e`.

## Reproduce

The raw instruction export contains instruction bytes and text, so keep it outside Git. Regenerate it from the same analyzed Ghidra project, then run the compact cross-check builder:

```sh
GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_function_instructions.sh \
  /home/pes/ghidra_projects nevergone_title_enemy libcocos2dcpp.so \
  /tmp/nevergone-runtime-function-instructions.jsonl 0x2d2f1c 0x544a60
python docs/evidence/semantic-program-graph-evaluation/nevergone-runtime-resource-loader-20261020/rebuild_gold.py \
  /tmp/nevergone-runtime-function-instructions.jsonl
PYTHONPATH=src revenginstr-semantic-program-graph-evaluate \
  docs/evidence/semantic-program-graph-v3/nevergone-runtime-correlation-20261020/semantic-program-graph.jsonl \
  docs/evidence/semantic-program-graph-evaluation/nevergone-runtime-resource-loader-20261020/gold-subgraphs.jsonl \
  --view exact-only \
  --output docs/evidence/semantic-program-graph-evaluation/nevergone-runtime-resource-loader-20261020/evaluation.json
```

The generator requires the P-code `CALL` rows, Ghidra instruction references, and graph call edges to agree exactly. It emitted 36 `exact_match` rows; the generated gold subgraph declares only those selected `calls` edges complete.

## Result

| Metric | Result |
| --- | ---: |
| Expected calls | 36 |
| Matched calls | 36 |
| Candidate precision / recall | 1.0 / 1.0 |
| Unsupported edge rate | 0% |
| Provenance completeness | 100% |
| Accepted edges / accepted-edge precision | 0 / `null` |

The independent instruction-reference export validates static direct-call edge extraction for these two function bodies. It does not establish runtime execution, function behavior, or accepted-edge accuracy. The runtime capture corroborates only that both function entries were observed; its completeness remains unknown. The raw function instructions export is not committed; its SHA-256 and size are recorded in `replay-manifest.json`, and the derived callsite evidence and gold subgraph are retained here.
