# Ghidra parameter-to-field stores

Export High-P-code STORE operations where a value traces through bounded
value-preserving operations from one function parameter, and the destination
traces through supported constant address expressions to a field rooted at
another parameter. The result is structural evidence only; it does not assign
class semantics to either parameter or the field offset.

The tab-separated row contract is
schemas/ghidra-parameter-store-field-v1.schema.json. Function identities and
addresses are program metadata. Parameter indices are zero-based decimal
strings, and destination offsets are signed hexadecimal strings.

Run against an already analyzed program:

    GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_parameter_store_field.sh       /path/to/projects project-name program-name 00401000 /tmp/parameter-stores.tsv

The runner uses read-only, no-analysis mode and an isolated script directory.
The exporter follows bounded High-P-code address expressions and strips
value-preserving operations before matching the source and destination
parameters.

It can additionally write `GhidraMemoryStoreAccess/1` JSONL facts for every
High-P-code `STORE` in the selected function, including stores whose address
cannot be resolved to a formal parameter. Give each invocation an opaque
program id so the facts join to a matching `GhidraFunctionPcodeCFG` artifact:

```sh
GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_parameter_store_field.sh \
  /path/to/projects project-name program-name 00401000 /tmp/parameter-stores.tsv \
  --memory-access-output /tmp/memory-stores.jsonl \
  --program-id 'consumer:analysis-id'
```

The sidecar records exact P-code operation keys, logical and physical memory
spaces, access and address-space geometry, the parameter-rooted byte offset
when proven, and the operation ids in its address derivation. Unresolved
addresses remain explicit possible effects. Its row contract is
[`GhidraMemoryStoreAccess/1`](../schemas/ghidra-memory-store-access-v1.schema.json).
The audit checks every sidecar row against the CFG; the file hash and row
indices are retained in `FieldStoreLoadDominanceAudit/2` output.

The runner requires the exporter completion marker in Ghidra's output as well
as a successful process exit. This catches Ghidra versions that report a
post-script exception but return a zero process status.

It can also emit a parameter-rooted field-load sidecar in the same decompilation
pass. See [parameter-rooted field loads](GHIDRA_PARAMETER_LOAD_FIELD.md). The
optional sidecar does not imply that a load and store access the same object.
