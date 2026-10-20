# Nevergone gameplay resource capture

This is the newer on-device capture from Nevergone 1.0.9 on the connected
Redmi Note 8 Pro (`begonia`, ARM32). The installed APK SHA-256 is
`e1b85fd36fa932e6de49fdab6e858a8bddbba233faef9817cd568ae6adfe51bf`; the
`libcocos2dcpp.so` SHA-256 is
`94b1ef6a9469e261183ac08199c5b0eb65c0c40b81918ca097bd32920828eb5e`.

The source trace ran from `2026-10-20T12:39:57.971Z` through
`2026-10-20T13:28:04.358Z`. It contains 356 JSONL rows: 147 native calls, 200
file-access observations, and the hook/module/header records. The call rows
include 49 each for `GameLevels::LoadGameLevels`,
`CCFileUtilsAndroid::getFileData`, and `cocos2d::Decode`. The resource profile
found 97 unique file paths. Raw paths, transient pointers, and buffer bytes are
not retained in this directory.

## Replay results

- All 49 `Decode` addresses and all 49 direct-call observations map exactly to
  the pinned semantic graph.
- The bounded transform probe checked 6,028 byte positions across 48
  non-empty calls. All 48 matched the consumer-reported formula: 45 sampled
  and 3 full-buffer checks. One zero-length call is inconclusive; no mismatch
  was observed.
- 34 selected `Decode` output-buffer / `getFileData` return-pointer pairs are
  witnessed, and the ledger routes all 34 to `review_required`. Nine
  observations had different pointers; six had no later same-thread
  `getFileData` return in the trace. They are excluded from the pair set.
- The adapter groups multiple `Decode` returns that share a candidate
  `getFileData` return and keeps a pair only when exactly one output pointer
  matches that return.

The source trace has no footer, and its 200 file-access rows reach the probe's
200-event limit. Capture completeness remains unknown. The probe ran in its
`scene`/`resources` profile with only three native hooks, so this capture adds
level/resource-loading evidence; it does not add combat or player-control
coverage. Runtime formula outcomes are consumer-reported, and RevEngInstr does
not recompute them from retained bytes.

The raw trace is not checked in because it contains process pointers and file
paths. Its SHA-256 is `edc93f7a8c2c178276e0d5c5dbbb9538833a8b9144748045ea8c5f0328a86c24`;
the normalized metadata records its size, row/event counts, and missing footer.
The trace was normalized with
[`nevergone_decode_to_runtime_observations.py`](../../../../tools/capture_adapters/nevergone_decode_to_runtime_observations.py)
and the same probe script used by the
[earlier device capture](../nevergone-decode-device-20261020/README.md). A
fresh value-token key was kept outside the repository.
