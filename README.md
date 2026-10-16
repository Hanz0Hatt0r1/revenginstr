# revenginstr

Reusable reverse-engineering analysis tooling extracted from the Nevergone and NFS Shift recompilation projects.

`revenginstr` contains project-neutral mechanisms, schemas and analysis code. Game-specific labels, addresses, class names, offsets and semantic evidence remain in consumer repositories.

## Initial scope

- architecture-normalized high-P-code export from Ghidra;
- portable corpus/schema validation and leakage checks;
- cross-project/OOD diagnostics;
- monotone foreign-project routing guards;
- shared ML/evidence contracts used by multiple recompilation projects.

## Boundary

The toolkit may know about architectures such as ARM32 and x86-32, and concepts such as P-code, callgraphs, receivers, vtables, family similarity and selective routing. It must not encode Nevergone `GameScene`/Cocos rules or NFS Shift retail addresses/`HDVehicle` offsets.

Current consumers:

- `Hanz0Hatt0r1/nevergone-recomp` — reference/training project;
- `Hanz0Hatt0r1/nfs-shift-decompilation` — first cross-project x86-32 consumer.

## Layout

```text
ghidra/                 generic Ghidra exporters
src/revenginstr/pcode/  portable corpus contracts/audits
src/revenginstr/ood/    cross-project safety guards
schemas/                stable data contracts
tests/                  generic tests
docs/                   architecture and migration notes
```

## Install for development

```bash
python -m pip install -e '.[test]'
pytest
```

## Portable P-code contract

The first stable interchange format is `REVENGINSTR.PcodeCorpus/1`. `model_text` is deliberately free of function names, absolute addresses, direct call target identity, strings/resources, instruction bytes and decompiler C. Outer `program`, `source_entry` and `source_name` fields are audit/join metadata only.

Consumer repositories own their datasets, weak labels, ground truth and semantic gates. Cross-project model output is triage/OOD evidence, not semantic authority.
