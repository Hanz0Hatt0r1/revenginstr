# Shift `00d83f90` field store/load replay

This bounded x86-32 replay uses read-only High-P-code, CFG/4, parameter-field,
and memory-store exports from the saved Ghidra Shift project. The executable
and Ghidra project are not included; committed exports are sufficient to
rebuild the analyzer outputs.

## Result

The field-pair builder emits one exact pair for `param3+0`: a four-byte
`LOAD@00d83fa1` at P-code time 28 and a four-byte `STORE@00d84019` at time 94.
The store occurs after the load. `FieldStoreLoadPathAudit/2` reports
`no_cfg_path`; `FieldStoreLoadDominanceAudit/7` reports
`store_not_dominating_load`, with a path from entry to the load that bypasses
the store. The function also has calls at times 37 and 69, both before the
tracked store. This is a negative structural example: an exact same-field
pair does not establish a store-to-load witness or memory reaching definition.

## Rebuild analyzer outputs

Run from the repository root with the project environment installed:

```sh
uv run --project . revenginstr-receiver-field-access-pairs \
  docs/evidence/field-store-load-shift-00d83f90/parameter-stores.tsv \
  docs/evidence/field-store-load-shift-00d83f90/parameter-loads.tsv \
  --program-id shift-fresh-d-region-00d83f90 \
  --memory-store-access-jsonl docs/evidence/field-store-load-shift-00d83f90/memory-store-access.jsonl \
  --output docs/evidence/field-store-load-shift-00d83f90/field-access-pairs.jsonl

uv run --project . revenginstr-receiver-field-store-load-audit \
  docs/evidence/field-store-load-shift-00d83f90/field-access-pairs.jsonl \
  docs/evidence/field-store-load-shift-00d83f90/function-pcode-cfg-v4.jsonl \
  --output docs/evidence/field-store-load-shift-00d83f90/path-audit.jsonl

uv run --project . revenginstr-receiver-field-store-load-dominance-audit \
  docs/evidence/field-store-load-shift-00d83f90/field-access-pairs.jsonl \
  docs/evidence/field-store-load-shift-00d83f90/function-pcode-cfg-v4.jsonl \
  --memory-store-access-jsonl docs/evidence/field-store-load-shift-00d83f90/memory-store-access.jsonl \
  --output docs/evidence/field-store-load-shift-00d83f90/dominance-audit.jsonl
```

## Artifact hashes

| Artifact | SHA-256 |
| --- | --- |
| Dominance audit/7 | `6d38c4ee83ef05e6a6b5a4c649d41f12226f293b3c144a0091c30b6711f268ca` |
| Field access pairs/1 | `13e15a1d490dcd2ceb7810a9dc47890d93463c9e72c529794968973306b017a2` |
| Ghidra function P-code CFG/4 | `423ada7d6e109db387f6b2e86d1be30c2061e6b38838e9159432bcd1a2db1291` |
| Ghidra function P-code flow/1 | `8c7db69d5d61871d4c6896663a4024d33a5f49e63e8cdaea819fba232164973b` |
| Ghidra memory store access/1 | `ef3c2568d49350ae01fa62abd3576e726e9f2c295a1fbada567e77bdf41b89eb` |
| Ghidra parameter load field/1 | `ae9bca495d9caa4378d42b15a665fa5751e8b7fba9b6f47317a51ef31f93395c` |
| Ghidra parameter store field/1 | `e6ec39452b9221d0dc18ab1849187bc501b73d9eda27703ce055486e35d90282` |
| Field store/load path audit/2 | `51c6bce62158841d3c1fd8fa27f9a57c8e8468d6052629e0e8e81286bcbc6537` |
