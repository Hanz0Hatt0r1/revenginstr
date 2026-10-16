# Ghidra program metadata index

`ExportGhidraProgramIndex.java` exports five gzip-compressed UTF-8 TSV tables
from the currently selected Ghidra program. This is the legacy
`REVENGINSTR.GhidraProgramIndex/1` bundle: individual rows have no in-band
`format` cell, so the exact filename suffix and header identify each table.
The versioned JSON Schemas describe decoded row objects; wire cells remain
strings. It records metadata only; strings are UTF-8 encoded as Base64, and the
exporter does not copy program bytes, decompiler output, or source assets.

| Suffix | Exact header | Row schema |
| --- | --- | --- |
| `.functions.tsv.gz` | `entry\tname\taddress_count\tis_external\tsignature` | [`functions/1`](../schemas/ghidra-program-index-functions-v1.schema.json) |
| `.symbols.tsv.gz` | `address\tname\ttype\tsource\tis_primary` | [`symbols/1`](../schemas/ghidra-program-index-symbols-v1.schema.json) |
| `.strings.tsv.gz` | `address\tutf8_base64\tlength` | [`strings/1`](../schemas/ghidra-program-index-strings-v1.schema.json) |
| `.xrefs.tsv.gz` | `from\tto\ttype\toperand\tsource` | [`xrefs/1`](../schemas/ghidra-program-index-xrefs-v1.schema.json) |
| `.calls.tsv.gz` | `caller_entry\tcall_site\tcallee_entry` | [`calls/1`](../schemas/ghidra-program-index-calls-v1.schema.json) |

Rows follow the corresponding Ghidra function, symbol, defined-data, or
reference iterator. The calls table filters the xref stream to direct call
references whose caller and callee resolve to functions. `address()` writes
`-` for a null address; cell text has tabs and line breaks replaced with spaces.
String bytes are UTF-8 Base64, while `length` is Java `String.length()` (UTF-16
code units), not Unicode code points. Program identity and executable digest
are not embedded in these tables; retain the invocation/program identity in the
consumer's artifact manifest.

The headers and row meanings are frozen for v1. A future in-band format or
column change requires a new bundle version and matching schemas; do not insert
columns into these tables in place.

```sh
GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_program_index.sh \
  /path/to/project project-name program-name /path/to/output/program
```

The runner opens the existing project read-only and disables analysis. Run it
against a project that has already completed any desired analysis. Address
values and coverage follow the selected Ghidra program and its reference map.
