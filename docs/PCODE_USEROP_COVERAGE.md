# P-code userop coverage

`revenginstr-pcode-userop-coverage` joins `CALLOTHER` userop indices from a
`REVENGINSTR.GhidraFunctionInstructions/1` corpus to the indexed names exported
by `REVENGINSTR.GhidraLanguageUserops/1`.

```bash
revenginstr-pcode-userop-coverage functions.jsonl.gz \
  functions.jsonl.gz.manifest.json language-userops.json \
  --output userop-coverage.json
```

The tool verifies that the corpus SHA matches its manifest, and that the
manifest and userop table have the same language id. It reports observed
indices, mapped names, and unmapped indices. Names are architecture metadata;
they do not constitute a userop implementation or prove recompilation
behavior.
