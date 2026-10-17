# Comparing Ghidra exporter output

`revenginstr-export-parity` compares two UTF-8 TSV exports by header and
decoded row values, preserving row order. It streams both files and does not
copy record contents into the report.

```bash
revenginstr-export-parity shared.tsv fallback.tsv --output parity.json
```

Exit status is `0` when headers and rows match, `1` when valid TSV records
differ, and `2` when an input cannot be read or parsed. The
[`GhidraExportParity/1` report](../schemas/ghidra-export-parity-v1.schema.json)
stores both input SHA-256 values, row counts, byte equality, record equality,
and the first differing header/row/count index. It intentionally omits paths
and TSV values, so the report can be retained beside consumer-owned evidence
without copying proprietary rows into this repository.

Record equality ignores byte-only differences such as LF versus CRLF. The
separate `same_bytes` field reports whether the original files have identical
bytes. The comparison does not establish that two exporters received the same
program or invocation; consumers should record those inputs in their own
evidence bundle.
