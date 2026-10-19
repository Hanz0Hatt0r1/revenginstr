# Runtime to static address correlation

`revenginstr-runtime-correlate` accepts one `SemanticProgramGraph/3`, a
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
revenginstr-runtime-correlate semantic-program-graph.jsonl static-identity.json \
  capture-manifest.json runtime-address-observations.jsonl \
  --output runtime-static-correlation.json
```

The Nevergone `CCJoyStick` graph has a synthetic replay that exercises address
normalization and sampling-gap handling. A separate bounded startup capture
from the installed game records function entries for two resource functions;
they remain unmatched because the pinned graph does not contain them. See
[`the device replay`](evidence/runtime-static-correlation-v1/nevergone-device-runtime-20261019/).
