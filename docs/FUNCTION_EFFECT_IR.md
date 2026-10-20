# Function Effect IR

`revenginstr-effect-ir` combines selected generic exporter rows into one
JSONL record per represented function. The default
`REVENGINSTR.FunctionEffectIR/1` projection contains parameter-rooted field
reads and writes plus direct calls, indirect calls, and return operations:

```sh
revenginstr-effect-ir --program-id 'analysis:opaque-id' \
  --parameter-stores parameter-stores.tsv \
  --parameter-loads parameter-loads.tsv \
  --memory-store-access memory-store-access.jsonl \
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
recovers the formal parameter and constant offset from High P-code. In
particular, `GhidraMemoryStoreAccess/1` contributes a field write only when it
reports an exact parameter root, constant byte offset, and STORE width.
`source_parameter_index` stays null for these rows because the sidecar does
not identify the stored value's source; unresolved locations are not projected
as field writes. Direct and
indirect call operations and `RETURN` operations are `exact_static`; unresolved
direct-call targets retain the `-` sentinel. Operation input tokens are
preserved where the P-code exporter provides them.

Opt in to `REVENGINSTR.FunctionEffectIR/2` to include every High-P-code
`LOAD` and `STORE` from the same P-code flow file:

```sh
revenginstr-effect-ir --program-id 'analysis:opaque-id' \
  --pcode-flow function-pcode-flow.tsv \
  --include-generic-memory-ops \
  --output function-effects-v2.jsonl
```

Version 2 labels these exact operations `memory_read` and `memory_write` with
the `exact_static` evidence class. It preserves the raw P-code input tokens;
the read row also carries the operation's output token. These rows do not
resolve an address to a global or parameter, infer an access width, establish
pointer aliasing, or claim that a write reaches a read. Parameter-rooted field
read/write facts keep their existing `derived_structural` class and provenance.
Version 1 remains the default and unchanged when the flag is omitted.
Benchmark manifests can select v2 by pinning the v2 schema and including the
flag in the `function-effect-ir` stage.

Neither version infers function roles, API categories, allocation/free
semantics, control patterns, or type meaning. A field write
and a later field read remain separate facts; the IR does not claim that the
write reaches the read. Labels and semantic truth stay in consumer-owned data.
