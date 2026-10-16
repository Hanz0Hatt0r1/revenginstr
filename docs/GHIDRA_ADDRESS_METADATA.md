# Ghidra address metadata

`ExportGhidraAddressMetadata.java` writes one `REVENGINSTR.GhidraAddressMetadata/1` JSONL row per requested address. Rows include memory-block permissions, the primary symbol, exact and containing function facts, instruction mnemonic, defined-data type, and the four raw bytes interpreted as a 32-bit word using the program endianness. The exporter reads an existing project and does not change analysis state.

```sh
GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_address_metadata.sh \
  /path/to/project project-name program-name metadata.jsonl 00401000 00402000
```

The output contract is defined in [`schemas/ghidra-address-metadata-v1.schema.json`](../schemas/ghidra-address-metadata-v1.schema.json).
