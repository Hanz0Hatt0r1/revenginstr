# Nevergone `Decode` runtime replay

This capture came from Nevergone 1.0.9 running on the connected Redmi Note 8
Pro (`begonia`, ARM32). The installed APK hash is recorded in
[`capture-metadata.json`](capture-metadata.json); it matches the APK installed
on the device after adding the bounded Frida observation hook. The target
`lib/armeabi-v7a/libcocos2dcpp.so` SHA-256 is
`94b1ef6a9469e261183ac08199c5b0eb65c0c40b81918ca097bd32920828eb5e`.

The capture has 11 observed calls to `cocos2d::Decode` at ELF VMA `0x534a40`,
which maps to graph entry `0x544a40` under the pinned `0x10000` image base. All
11 runtime addresses join to the same exact function node in the pinned
SemanticProgramGraph/4. Ten calls had non-empty buffers; the probe compared 128
evenly spaced byte positions per call, and all 1,280 positions matched
`dst[i] = (((src[i] XOR key) - (i mod 127)) mod 256)` with `key = 1`. The
remaining call had length zero, so it is inconclusive. No buffer bytes or raw
data pointers are retained in the normalized observations.

Replay results are 10 `sampled_match`, 0 `observed_mismatch`, and 1
`inconclusive`. Capture completeness is `unknown`: the trace kit samples calls
after its initial per-symbol window, and no complete call count is available.
The runtime replay records a consumer-reported result; it does not authenticate
the probe or recompute the formula from the omitted bytes. It does not prove
whole-buffer behavior or close the receiver/field/state value-flow pairs in
M9.4.

The same 11 events also verify the caller edge. Frida recorded return offset
`0x534be1`; clearing the Thumb state bit and stepping back the four-byte `BL`
maps it to ELF call instruction `0x534bdc`, then to graph operation `0x544bdc`
under image base `0x10000`. The pinned graph identifies that operation as the
unique `CALL` from `CCFileUtilsAndroid::getFileData` (`0x544a60`) to `Decode`
(`0x544a40`). [`RuntimeDirectCallCorrelation/1`](../../../../docs/RUNTIME_DIRECT_CALL_CORRELATION.md)
reports 11/11 matched edges. The source disassembly is retained in the
[mobile static-analysis evidence](../../mobile-static-analysis-v1/nevergone-decode-20261020/disassembly.txt).

`probe-script.js` is the complete instrumented trace script used for this
capture. The raw device trace is not checked in because it contains transient
process pointers and file-access paths; its SHA-256 is retained in the capture
metadata. Recreate the normalized capture with:

```sh
python tools/capture_adapters/nevergone_decode_to_runtime_observations.py \
  /path/to/nevergone-trace.jsonl \
  --probe-script docs/evidence/runtime-behavior-replay-v1/nevergone-decode-device-20261020/probe-script.js \
  --semantic-graph docs/evidence/semantic-program-graph-v4/nevergone-runtime-call-arguments-20261020/semantic-program-graph.jsonl \
  --capture-id nevergone-decode-device-20261020-pid15911 \
  --installed-apk-sha256 e1b85fd36fa932e6de49fdab6e858a8bddbba233faef9817cd568ae6adfe51bf \
  --output-dir /tmp/nevergone-decode-capture

PYTHONPATH=src python -m revenginstr.runtime_static_correlation \
  docs/evidence/semantic-program-graph-v4/nevergone-runtime-call-arguments-20261020/semantic-program-graph.jsonl \
  /tmp/nevergone-decode-capture/static-identity.json \
  /tmp/nevergone-decode-capture/capture-manifest.json \
  /tmp/nevergone-decode-capture/runtime-address-observations.jsonl \
  --output /tmp/nevergone-decode-capture/runtime-static-correlation.json

PYTHONPATH=src python -m revenginstr.runtime_direct_call_correlation \
  docs/evidence/semantic-program-graph-v4/nevergone-runtime-call-arguments-20261020/semantic-program-graph.jsonl \
  /tmp/nevergone-decode-capture/static-identity.json \
  /tmp/nevergone-decode-capture/capture-manifest.json \
  /tmp/nevergone-decode-capture/runtime-direct-call-observations.jsonl \
  --output /tmp/nevergone-decode-capture/runtime-direct-call-correlation.json

python tools/capture_adapters/pin_runtime_transform_manifest.py \
  /tmp/nevergone-decode-capture/capture-metadata.json \
  /tmp/nevergone-decode-capture/runtime-static-correlation.json \
  /tmp/nevergone-decode-capture/runtime-transform-observations.jsonl \
  --output /tmp/nevergone-decode-capture/runtime-transform-manifest.json

PYTHONPATH=src python -m revenginstr.runtime_transform_replay \
  /tmp/nevergone-decode-capture/runtime-transform-manifest.json \
  /tmp/nevergone-decode-capture/runtime-static-correlation.json \
  /tmp/nevergone-decode-capture/runtime-transform-observations.jsonl \
  --output /tmp/nevergone-decode-capture/runtime-transform-replay.json
```

The checked-in address, direct-call, and transform correlations, observations,
manifest, and replay are the hash-pinned outputs from those steps. A fresh
capture needs a manifest whose hashes refer to that capture's files.
