# Function Effect IR

`revenginstr-effect-ir` combines selected generic exporter rows into one
`REVENGINSTR.FunctionEffectIR/1` JSONL record per represented function. The
first version projects parameter-rooted field reads and writes plus direct
calls, indirect calls, and return operations:

```sh
revenginstr-effect-ir --program-id 'analysis:opaque-id' \
  --parameter-stores parameter-stores.tsv \
  --parameter-loads parameter-loads.tsv \
  --pcode-flow function-pcode-flow.tsv \
  --output function-effects.jsonl
```

Any one or more input files may be selected. The program id is caller-owned and
is carried through as an opaque join key. The tool rejects unexpected headers,
unsupported field-store/load formats or statuses, malformed numeric keys,
invalid UTF-8, and inputs that exceed the effect budget before writing output.
Pinned benchmark manifests can invoke it with the `function-effect-ir` stage
tool and validate the JSONL output against the same versioned schema.

Each effect contains its operation address/time, opcode, structural fields, an
evidence class, and provenance. Provenance includes the SHA-256 of the exact
input bytes and the one-based data-record ordinal. Effect ids are derived from
those values, so they are stable across paths and runs while remaining
traceable to the pinned artifact. Function records sort by function entry;
effects sort by operation address, sequence time, kind, then effect id.

Parameter-rooted reads and writes are `derived_structural`: the exporter
recovers the formal parameter and constant offset from High P-code. Direct and
indirect call operations and `RETURN` operations are `exact_static`; unresolved
direct-call targets retain the `-` sentinel. Operation input tokens are
preserved where the P-code exporter provides them.

This initial projection does not infer function roles, API categories,
allocation/free semantics, control patterns, or type meaning. A field write
and a later field read remain separate facts; the IR does not claim that the
write reaches the read. Labels and semantic truth stay in consumer-owned data.
