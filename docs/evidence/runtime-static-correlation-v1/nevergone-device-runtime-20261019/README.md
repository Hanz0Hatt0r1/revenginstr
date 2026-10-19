# Nevergone startup runtime capture

This replay comes from one launch of the installed Nevergone 1.0.9 APK on the connected Android device on 2026-10-19. Its bundled Frida Gadget used the APK `resources` trace profile. The source log was read from the app private files directory, then reduced to function-entry addresses; raw paths, pointer values, process identifiers, and device identifiers are not checked in.

The capture has 88 emitted function-entry records: 46 for `CCFileUtilsAndroid::getFileData` and 42 for `GameLevels::LoadGameLevels`. The trace hook retained the first 40 calls per symbol and then sampled every 25th call. The source trace uses per-symbol ordinals while this schema uses a global sequence, so exact interleaved sampling gaps cannot be reconstructed. Capture completeness remains `unknown`.

The Frida module base was `0xbb64c000`. The installed ELF's lowest `PT_LOAD` virtual address is zero; normalizing runtime addresses yields static function entries `0x544a60` and `0x2d2f1c`. Read-only Ghidra P-code exports verify these as `cocos2d::CCFileUtilsAndroid::getFileData` and `GameLevels::LoadGameLevels`. The replay graph includes both exact function entries, so all 88 observations match with no ambiguous or unmatched records.

## Reproduce runtime correlation

From the repository root:

```sh
PYTHONPATH=src python -m revenginstr.runtime_static_correlation \
  docs/evidence/semantic-program-graph-v3/nevergone-runtime-correlation-20261020/semantic-program-graph.jsonl \
  docs/evidence/runtime-static-correlation-v1/nevergone-device-runtime-20261019/static-identity.json \
  docs/evidence/runtime-static-correlation-v1/nevergone-device-runtime-20261019/capture-manifest.json \
  docs/evidence/runtime-static-correlation-v1/nevergone-device-runtime-20261019/observations.jsonl \
  --output docs/evidence/runtime-static-correlation-v1/nevergone-device-runtime-20261019/correlation.json
```

The current report has 88 matched events, zero ambiguous events, and zero unmatched events. The static identity and capture manifest pin the graph SHA-256 and identity SHA-256.

## Decision-ledger replay

```sh
PYTHONPATH=src revenginstr-runtime-ledger \
  docs/evidence/runtime-static-correlation-v1/nevergone-device-runtime-20261019/correlation.json \
  --output docs/evidence/runtime-static-correlation-v1/nevergone-device-runtime-20261019/decision-ledger-events.jsonl
revenginstr-decision-ledger-audit \
  docs/evidence/runtime-static-correlation-v1/nevergone-device-runtime-20261019/decision-ledger-events.jsonl \
  --output docs/evidence/runtime-static-correlation-v1/nevergone-device-runtime-20261019/decision-ledger-audit.json
```

All 88 matches become `review_required` with `human_review`; the audit has zero accepted claims. Matching a runtime address to a static function entry does not establish that the sampled calls describe exhaustive behavior or automatically accept a reconstruction. `replay-manifest.json` pins the graph, Ghidra exports, correlation, ledger, and audit outputs.
