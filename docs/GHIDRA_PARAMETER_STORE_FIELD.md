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

It can also emit a parameter-rooted field-load sidecar in the same decompilation
pass. See [parameter-rooted field loads](GHIDRA_PARAMETER_LOAD_FIELD.md). The
optional sidecar does not imply that a load and store access the same object.
