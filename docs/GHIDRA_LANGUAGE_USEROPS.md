# Ghidra language userop inventory

`ExportGhidraLanguageUserops.java` exports the selected language's indexed
userop-name table as `REVENGINSTR.GhidraLanguageUserops/1`. Each `CALLOTHER`
operation's first constant input is its language-scoped userop index; this
table resolves that index without treating it as a global identity.

Run against an already analyzed Ghidra program:

```bash
GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_language_userops.sh \
  /path/to/project ProjectName program /tmp/language-userops.json
```

The runner opens the existing program read-only without analysis and validates
that the exported indices are contiguous and the declared count matches the
rows. Names are language metadata only; they do not describe userop semantics
or provide an implementation for a recompilation backend.
