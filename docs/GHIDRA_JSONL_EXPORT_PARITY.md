# Comparing Ghidra JSONL exporter output

`revenginstr-jsonl-export-parity` compares UTF-8 JSONL exports one object per
line. It preserves record order and ignores JSON object key order. The report
contains hashes, record counts, byte equality, semantic record equality, and
the first differing record index; it never contains exported values or paths.

```bash
revenginstr-jsonl-export-parity shared.jsonl fallback.jsonl --output parity.json
```

Exit status is `0` when all JSON objects match in order, `1` when valid records
differ, and `2` when an input cannot be read or parsed. Blank lines, duplicate
object keys, non-object top-level values, and non-standard JSON constants fail
closed. The [`GhidraJsonlExportParity/1` report](../schemas/ghidra-jsonl-export-parity-v1.schema.json)
omits both input paths and record contents so consumers can retain a compact
parity result beside their own evidence.

Record equality does not establish that two exporters received the same
program or invocation. Consumers should pin the program hash, exporter source
commit, and invocation details in their own evidence bundle.
