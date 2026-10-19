# Runtime indirect-call correlation

`revenginstr-runtime-indirect-call-correlate` joins a bounded runtime event to
the exact caller function, `CALLIND` operation address, and executed target
function in one hash-pinned `SemanticProgramGraph/3`. It takes a
`RuntimeStaticIdentity/1`, the capture manifest already used by runtime address
correlation, and `RuntimeIndirectCallObservation/1` rows:

```sh
revenginstr-runtime-indirect-call-correlate \
  semantic-program-graph.jsonl static-identity.json capture-manifest.json \
  indirect-call-observations.jsonl --output indirect-call-correlation.json
```

Each observation contains the caller entry address, the machine address of the
indirect call site, and the target entry address as seen in that capture. The
tool maps all three with the module delta pinned by the capture and static
identity. It joins the call site by caller entry plus operation address and
`CALLIND` opcode; if multiple operations share that identity, the site remains
ambiguous. Target and caller addresses join only to exact function entries.
Sequence numbers order this call-event stream; declared sampling-gap ranges use
the same sequence coordinates and describe missing call events in this stream.

Caller, call-site, and target statuses stay separate. Unmatched runtime targets,
ambiguous graph identities, mapping underflow/overflow, sampling gaps, and all
input hashes remain visible. An address outside the graph can be an observed
runtime target address while its function identity remains unmatched. The
report does not promote static candidate sets or claim unobserved targets are
impossible. Consumers control whether and how runtime instrumentation is
captured; this command only correlates supplied observations.
