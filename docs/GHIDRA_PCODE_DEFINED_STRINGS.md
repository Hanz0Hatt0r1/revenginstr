# Ghidra P-code defined strings

`ExportGhidraPcodeDefinedStrings.java` takes a metadata-only P-code TSV and
resolves only constant tokens of the form `const:0xADDRESS:SIZE` that point
inside already-defined Ghidra `String` data. It does not scan or export other
strings from the program.

Each output TSV row uses `REVENGINSTR.GhidraPcodeDefinedString/1` and contains
the constant address, defined data address, byte offset, UTF-8 text encoded as
base64, and Java string length. The schema is
`schemas/ghidra-pcode-defined-strings-v1.schema.json`.

Run it against an existing analyzed program:

```bash
GHIDRA_HOME=/opt/ghidra \
  scripts/run_ghidra_pcode_defined_strings.sh \
  /path/to/projects project-name program-name function-flow.tsv defined-strings.tsv
```

The runner uses `-readOnly -noanalysis` and a temporary script path. Program
addresses and string contents remain evidence from the selected consumer
project; the exporter has no title-specific names or interpretation.
