# Ghidra parameter-rooted field loads

The parameter-store exporter can optionally emit High-P-code `LOAD` operations
whose address resolves to a constant offset rooted at one function parameter.
The load row preserves the function entry, operation address/time, formal
parameter index, offset expression kind, result size, and result varnode token.
This is structural evidence only; it does not join a load to a store or infer
that two parameter instances refer to the same object.

The optional row contract is
[`GhidraParameterLoadField/1`](../schemas/ghidra-parameter-load-field-v1.schema.json).
Existing store-only invocation and output remain unchanged. To export both
artifacts from the same decompilation:

```sh
GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_parameter_store_field.sh \
  /path/to/projects project-name program-name 00401000 /tmp/stores.tsv \
  --load-output /tmp/loads.tsv
```

Both files come from one analyzed function in the selected program. A later
store/load join must still establish base compatibility explicitly; field
offset equality alone is not enough.
