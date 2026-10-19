# Runtime to static address correlation

`revenginstr-runtime-correlate` accepts one `SemanticProgramGraph/3`, a
caller-pinned `RuntimeStaticIdentity/1`, one `RuntimeCaptureManifest/1`, and
bounded `RuntimeAddressObservation/1` JSONL rows. It subtracts the explicitly
recorded load bias from runtime addresses, then joins function events only to
exact graph function entries and instruction events only to exact graph
operation addresses.

Addresses must be plain hexadecimal values in one flat image space.
`function_entry`, `function_exit`, and `call_target` rows carry the function
entry address; `instruction` rows carry the P-code operation address. Other
address encodings fail closed.

The identity manifest pins both the executable SHA-256 and exact graph bytes.
The capture repeats the executable identity and pins the identity manifest.
Mismatches fail closed. One capture uses one load bias and one main image;
unmatched, ambiguous P-code addresses, mapping underflow/overflow, and declared
sample gaps are reported separately. The tool does not infer address ranges, resolve
object identities or fields, or execute probes. A function/instruction join
is only a location correlation, not runtime value-flow confirmation.

```sh
revenginstr-runtime-correlate semantic-program-graph.jsonl static-identity.json \
  capture-manifest.json runtime-address-observations.jsonl \
  --output runtime-static-correlation.json
```

The Nevergone `CCJoyStick` graph has a synthetic test capture that exercises
load-bias normalization and sampling-gap handling. It is not runtime evidence
from the game. A real capture must come from a consumer-approved bounded probe
and pin the exact executable and graph identities before correlation.
