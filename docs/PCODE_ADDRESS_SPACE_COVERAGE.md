# P-code address-space coverage

`revenginstr-pcode-address-space-coverage` resolves the first constant input of
raw P-code `LOAD` and `STORE` operations against a Ghidra language's exported
address-space table.

```bash
revenginstr-pcode-address-space-coverage functions.jsonl.gz \
  functions.jsonl.gz.manifest.json language-address-spaces.json \
  --output address-space-coverage.json
```

The tool verifies the corpus SHA-256 and exact language id before counting
loads and stores by space. It reports unknown IDs without guessing a space
name. The result describes corpus coverage; it does not implement guest memory
or claim that the P-code is executable.
