# Runtime to static address correlation

`revenginstr-runtime-static-correlate` accepts one `SemanticProgramGraph/3` or `/4`, a
caller-pinned `RuntimeStaticIdentity/1`, one `RuntimeCaptureManifest/1`, and
bounded `RuntimeAddressObservation/1` JSONL rows. The identity records the
static analyzer image base; the capture records the runtime module address
corresponding to ELF virtual address zero. The tool derives their delta and
subtracts it from runtime addresses before joining function events only to
exact graph function entries and instruction events only to exact graph
operation addresses.

Addresses must be plain hexadecimal values in one flat image space.
`function_entry`, `function_exit`, and `call_target` rows carry the function
entry address; `instruction` rows carry the P-code operation address. Other
address encodings fail closed.

The identity manifest pins the executable SHA-256, exact graph bytes, and
static image base. The capture repeats the executable identity and pins the
identity manifest. Mismatches fail closed. One capture uses one runtime module
base and one static image base; unmatched, ambiguous P-code addresses, mapping
underflow/overflow, and declared sample gaps are reported separately. The tool
does not infer address ranges, resolve object identities or fields, or execute
probes. A function/instruction join is only a location correlation, not
runtime value-flow confirmation.

```sh
revenginstr-runtime-static-correlate semantic-program-graph.jsonl static-identity.json \
  capture-manifest.json runtime-address-observations.jsonl \
  --output runtime-static-correlation.json
```

The Nevergone `CCJoyStick` graph has a synthetic replay that exercises address
normalization and sampling-gap handling. The first device replay used a graph
without the resource functions and correctly left those events unmatched. A
follow-up SemanticProgramGraph/4 replay includes the two functions and matches
all 88 startup observations; a later bounded capture also exact-matches 11
`Decode` entries. See the [graph replay](evidence/runtime-static-correlation-v1/nevergone-device-runtime-20261019/)
and [runtime transform replay](RUNTIME_TRANSFORM_REPLAY.md).
For exact caller/`CALLIND`/target triples, see
[`runtime indirect-call correlation`](RUNTIME_INDIRECT_CALL_CORRELATION.md).
