# Nevergone startup runtime capture

This replay is derived from one launch of the installed Nevergone 1.0.9 APK on the connected Android device on 2026-10-19. Its bundled Frida Gadget used the APK's `resources` trace profile. The source log was read from the app's private files directory after the run, then reduced to function-entry addresses; raw paths, pointer values, process identifiers, and device identifiers are not checked in.

The capture contains 88 emitted function-entry records: 46 for `CCFileUtilsAndroid::getFileData` and 42 for `GameLevels::LoadGameLevels`. The trace hook retained the first 40 calls per symbol and then sampled every 25th call. Because the source trace uses per-symbol ordinals while this schema uses one global sequence, the omitted interleaved call positions cannot be represented as exact `sampling_gaps`; the manifest therefore marks completeness `unknown`.

The Frida module base was `0xbb64c000`. The installed ELF's lowest `PT_LOAD` virtual address is zero, so the correlator maps runtime addresses by subtracting `runtime_module_base - static_image_base`. This produces static addresses `0x544a60` and `0x2d2f1c`. Neither function is present in the pinned `CCJoyStick` graph, so all 88 rows are retained as unmatched. This is a real runtime capture and an explicit graph-coverage limit, not a failed address conversion.

Reproduce the report from the repository root:

```sh
PYTHONPATH=src python -m revenginstr.runtime_static_correlation \
  docs/evidence/semantic-program-graph-v3/nevergone-ccjoystick/semantic-program-graph.jsonl \
  docs/evidence/runtime-static-correlation-v1/nevergone-synthetic/static-identity.json \
  docs/evidence/runtime-static-correlation-v1/nevergone-device-runtime-20261019/capture-manifest.json \
  docs/evidence/runtime-static-correlation-v1/nevergone-device-runtime-20261019/observations.jsonl \
  --output /tmp/nevergone-device-runtime-correlation.json
```
