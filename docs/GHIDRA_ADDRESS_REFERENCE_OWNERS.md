# Ghidra address reference owners

`ExportGhidraAddressReferenceOwners.java` exports direct references to the
addresses supplied by its caller. Each row includes the target, reference
location/type/source/operand, instruction mnemonic and containing function
identity. A target with no references gets one row with `-` reference fields.

The output uses `REVENGINSTR.GhidraAddressReferenceOwner/1`, described by
`schemas/ghidra-address-reference-owners-v1.schema.json`. The exporter reports
program evidence only; it does not classify addresses or infer classes.

```bash
GHIDRA_HOME=/opt/ghidra \
  scripts/run_ghidra_address_reference_owners.sh \
  /path/to/projects project-name program-name references.tsv 00401000 00402000
```

The runner uses an isolated script path with `-readOnly -noanalysis`.
