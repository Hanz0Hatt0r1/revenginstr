# Nevergone runtime function coverage in SemanticProgramGraph/3

This replay adds exact Ghidra P-code evidence for the two functions observed in the Nevergone 1.0.9 startup trace. The source ELF SHA-256 is `94b1ef6a9469e261183ac08199c5b0eb65c0c40b81918ca097bd32920828eb5e`, matching the installed artifact and runtime capture.

## Exact function exports

The read-only runner consumes the existing analyzed `nevergone_title_enemy` Ghidra project. It writes P-code TSV metadata, not decompiler pseudocode:

```sh
GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_function_pcode_flow.sh \
  /home/pes/ghidra_projects nevergone_title_enemy libcocos2dcpp.so 0x2d2f1c \
  docs/evidence/runtime-static-correlation-v1/nevergone-device-runtime-20261019/LoadGameLevels.pcode-flow.tsv
GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_function_pcode_flow.sh \
  /home/pes/ghidra_projects nevergone_title_enemy libcocos2dcpp.so 0x544a60 \
  docs/evidence/runtime-static-correlation-v1/nevergone-device-runtime-20261019/CCFileUtilsAndroid-getFileData.pcode-flow.tsv
```

Ghidra identifies the entries as `GameLevels::LoadGameLevels` and `cocos2d::CCFileUtilsAndroid::getFileData`; the exports contain 46 and 597 P-code rows respectively. Both addresses were present as exact function entries in the analyzed program.

## Build the graph

```sh
PYTHONPATH=src revenginstr-effect-ir \
  --program-id nevergone-1.0.9-armv7-libcocos2dcpp \
  --pcode-flow docs/evidence/runtime-static-correlation-v1/nevergone-device-runtime-20261019/LoadGameLevels.pcode-flow.tsv \
  --output docs/evidence/runtime-static-correlation-v1/nevergone-device-runtime-20261019/LoadGameLevels.function-effect-ir.jsonl
PYTHONPATH=src revenginstr-effect-ir \
  --program-id nevergone-1.0.9-armv7-libcocos2dcpp \
  --pcode-flow docs/evidence/runtime-static-correlation-v1/nevergone-device-runtime-20261019/CCFileUtilsAndroid-getFileData.pcode-flow.tsv \
  --output docs/evidence/runtime-static-correlation-v1/nevergone-device-runtime-20261019/CCFileUtilsAndroid-getFileData.function-effect-ir.jsonl
```

Recreate the combined Effect IR input, including the two earlier player-facing rows, from the repository root:

```sh
python - <<'PY'
import json
from pathlib import Path

inputs = [
    Path("docs/evidence/semantic-program-graph-evaluation/nevergone-player-horizontal-facing/nevergone-facing-effects.jsonl"),
    Path("docs/evidence/runtime-static-correlation-v1/nevergone-device-runtime-20261019/LoadGameLevels.function-effect-ir.jsonl"),
    Path("docs/evidence/runtime-static-correlation-v1/nevergone-device-runtime-20261019/CCFileUtilsAndroid-getFileData.function-effect-ir.jsonl"),
]
rows = [json.loads(line) for path in inputs for line in path.read_text().splitlines() if line]
rows.sort(key=lambda row: row["function_entry"])
output = Path("docs/evidence/semantic-program-graph-v3/nevergone-runtime-correlation-20261020/function-effects.jsonl")
output.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows))
PY
```

Rebuild the graph from the repository root:

```sh
PYTHONPATH=src python -m revenginstr.semantic_program_graph \
  docs/evidence/semantic-program-graph-v3/nevergone-runtime-correlation-20261020/function-effects.jsonl \
  --type-layout-hypotheses docs/evidence/semantic-program-graph-v3/nevergone-ccjoystick/type-layout-hypothesis.jsonl \
  --output docs/evidence/semantic-program-graph-v3/nevergone-runtime-correlation-20261020/semantic-program-graph.jsonl
```

The Effect IR input has four function rows. The graph contains 29 function nodes, including linked call targets, alongside the reviewed `CCJoyStick` layout; it has 90 nodes and 128 edges. Its graph SHA-256 and every input artifact digest are pinned in `manifest.json`.
