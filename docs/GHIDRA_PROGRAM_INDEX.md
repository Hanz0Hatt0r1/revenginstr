# Ghidra program metadata index

`ExportGhidraProgramIndex.java` exports five gzip-compressed UTF-8 TSV tables
from the currently selected Ghidra program. It records metadata only; strings
are UTF-8 encoded as Base64, and the exporter does not copy program bytes,
decompiler output, or source assets.

| Suffix | Columns |
| --- | --- |
| `.functions.tsv.gz` | entry, name, address count, external flag, signature |
| `.symbols.tsv.gz` | address, name, type, source, primary flag |
| `.strings.tsv.gz` | address, UTF-8 Base64 value, Java string length |
| `.xrefs.tsv.gz` | source address, target address, reference type, operand, source |
| `.calls.tsv.gz` | caller entry, call site, callee entry for resolved direct calls |

```sh
GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_program_index.sh \
  /path/to/project project-name program-name /path/to/output/program
```

The runner opens the existing project read-only and disables analysis. Run it
against a project that has already completed any desired analysis. Address
values and coverage follow the selected Ghidra program and its reference map.
