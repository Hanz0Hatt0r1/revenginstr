# Nevergone post-Tap-to-Start menu capture

This capture comes from the trace-enabled Nevergone 1.0.9 build on a Redmi
Note 8 Pro (`begonia`, ARM32). The installed APK SHA-256 is
`e1b85fd36fa932e6de49fdab6e858a8bddbba233faef9817cd568ae6adfe51bf`; the
`libcocos2dcpp.so` SHA-256 is
`94b1ef6a9469e261183ac08199c5b0eb65c0c40b81918ca097bd32920828eb5e`.
The local signed APK and installed APK have the same hash, so a rebuild or
reinstall was unnecessary for this check.

## Tap-to-start check

On 2026-10-20, a cold launch displayed an Android native-library warning for
`libcocos2dcpp.so`'s relative `DT_NEEDED` entry
`./obj/local/armeabi-v7a/libffmpeg.so`. The device log says the linker allows
this for the app's target API 17. After dismissing the warning, the title
screen appeared. Tapping **Tap to start** opened the existing save-selection
screen (`DAWN Lv.6`, `Time 01:09`); the app process and its activity remained
active six seconds later, with no fatal-exception or signal-crash lines in
the bounded logcat snapshot. The run stopped at save selection before choosing
`New Story`, `Delete`, or `Play`.

## Replay results

- The capture recorded 42 `cocos2d::Decode` calls. All 42 addresses and all 42
direct-call observations map exactly to the pinned semantic graph.
- 41 calls reported formula matches: 38 sampled checks and 3 full-buffer
  checks. One zero-length call is inconclusive; no mismatch was observed.
- 34 selected `Decode` output-buffer / `getFileData` return-pointer pairs are
  witnessed, and the ledger marks all 34 `review_required`. Eight other
  observations were excluded: four ambiguous candidate pairings, three
  pointer mismatches, and one without a later same-thread return.

The source trace ran from `2026-10-20T13:48:06.782Z` through
`2026-10-20T13:49:21.884Z`. It contains 339 JSONL rows: 130 call rows (42 each
for `GameLevels::LoadGameLevels` and `cocos2d::Decode`, 46 for
`CCFileUtilsAndroid::getFileData`), 200 file-access observations, and nine
hook, loader, module, and header records. It has no footer and reaches the
200-file-event cap, so capture completeness remains unknown. The probe used
its `scene`/`resources` profile and three native hooks.

The raw trace is not checked in because it contains transient process pointers
and file paths. Its SHA-256 is
`fe684bec8e41de6b99b53cdb9377299ba564e887624b16ef698942b7536f2957`. The
normalized files here were produced by
[`nevergone_decode_to_runtime_observations.py`](../../../../tools/capture_adapters/nevergone_decode_to_runtime_observations.py)
using the same pinned probe and semantic graph as the
[earlier device capture](../nevergone-decode-device-20261020/README.md). A
capture-scoped HMAC token key remains outside the repository.
