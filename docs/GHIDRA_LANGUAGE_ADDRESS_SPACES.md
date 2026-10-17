# Ghidra language address spaces

`ExportGhidraLanguageAddressSpaces.java` writes the selected language's
`AddressSpace` IDs, names, pointer widths, addressable unit sizes, endianness,
and space-kind flags as `REVENGINSTR.GhidraLanguageAddressSpaces/1`.

The language-scoped ID table is required to interpret the special constant
input of raw P-code `LOAD` and `STORE` operations. Use the runner against an
already analyzed project:

```bash
GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_language_address_spaces.sh \
  /path/to/project ProjectName program /tmp/language-address-spaces.json
```

The runner opens the existing program read-only without analysis. These IDs
must only be joined to P-code from the exact same language id. Space metadata
provides addressing facts, not the contents of memory or the semantics of a
whole program.
