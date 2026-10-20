# Runtime direct-call correlation

`revenginstr-runtime-direct-call-correlate` joins a consumer-observed runtime
call instruction and target entry to a pinned `SemanticProgramGraph/3` or `/4`.
The caller is recovered from the unique static owner of the exact `CALL`
operation. A result is `matched` only when the callsite, caller, runtime target,
and the operation's single static target all agree.

`RuntimeDirectCallObservation/1` carries the exact instruction address and the
observed target function entry. Consumers that start with a return address
must normalize it to the call instruction using target-architecture evidence
before creating the observation. The correlator preserves address mapping,
sampling status, ambiguity, unresolved static targets, and hash provenance.
It does not infer completeness, object identity, or memory/value flow, and it
never upgrades a runtime edge to an accepted analysis claim.

```sh
revenginstr-runtime-direct-call-correlate semantic-program-graph.jsonl \
  static-identity.json capture-manifest.json \
  runtime-direct-call-observations.jsonl \
  --output runtime-direct-call-correlation.json
```

The Nevergone capture correlates 11 observed calls from
`CCFileUtilsAndroid::getFileData` to `cocos2d::Decode`; see the
[device replay](evidence/runtime-behavior-replay-v1/nevergone-decode-device-20261020/README.md).
