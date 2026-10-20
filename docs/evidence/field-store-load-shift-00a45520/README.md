# Shift `00a45520` field store/load replay

This x86-32 replay uses read-only exports from the existing Ghidra project for
`SHIFT.exe` (Ghidra 12.1.2 DEV). The program bytes have SHA-256
`eca479aa2d8dbb88bc55709d91ae5c7159ae1b00fc9555d6701000c26de8aee1`; the
executable and project are not committed. The committed capture is sufficient
to reproduce the RevEngInstr outputs.

## Result

The parameter-field exporter produced one store (`param0+0`, value from
parameter 3) and two loads at times 39 and 107. The general memory-store
exporter produced eight STORE facts: the parameter-rooted store at time 30,
the memory-only rooted store at time 109, and six stores with unresolved
destinations at times 54, 60, 67, 70, 72, and 84. The pair builder emitted
four pairs. All four paths are `candidate_path_compatible`, but this does not
clear intervening memory effects.

The CFG/4 dominance replay produced:

- `/6` `unique_cfg_store_candidate` for `STORE@00a45533` (time 30, `param0+0`,
  value from parameter 3) → `LOAD@00a45540` (time 39).
- `/6` `possible_intervening_memory_effect` for the same store →
  `LOAD@00a45572` (time 107). Six unresolved STORE destinations remain on the
  witness, and `CALL@00a4556d` at time 102 has an explicit memory-write
  effect through callee `00a40550`.
- `/7` `store_not_dominating_load` for the memory-only `STORE@00a45572` at time
  109 paired with either load; the store follows the later load at time 107.

This replay exercises the unknown-store and write-capable-call barriers while
retaining an earlier positive candidate. The path audit's compatible status
does not override those barriers. No runtime execution or memory reaching
definition is claimed.

## Rebuild Ghidra exports

Run from the repository root against the already imported, read-only project:

```sh
GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_function_pcode_cfg.sh \
  /home/pes/ghidra_projects nfs_shift_vulkan_runtime_20261018 SHIFT.exe \
  docs/evidence/field-store-load-shift-00a45520/function-pcode-cfg-v4.jsonl \
  nfs-shift:SHIFT.exe 00a45520 --indirect-effect-links

GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_parameter_store_field.sh \
  /home/pes/ghidra_projects nfs_shift_vulkan_runtime_20261018 SHIFT.exe \
  00a45520 docs/evidence/field-store-load-shift-00a45520/parameter-stores.tsv \
  --load-output docs/evidence/field-store-load-shift-00a45520/parameter-loads.tsv \
  --memory-access-output docs/evidence/field-store-load-shift-00a45520/memory-store-access.jsonl \
  --program-id nfs-shift:SHIFT.exe
```

`bounded-pcode.tsv` freezes the caller and direct callee flows. Its rows are
partitioned into the included TSVs used to rebuild the direct-call sidecar.

## Rebuild analyzer outputs

Run from the repository root with the project environment installed:

```sh
uv run --project . revenginstr-direct-call-memory-effects \
  docs/evidence/field-store-load-shift-00a45520/function-pcode-flow.tsv \
  --program-id nfs-shift:SHIFT.exe \
  --callee-flow 00a40550 docs/evidence/field-store-load-shift-00a45520/callee-pcode-flow/00a40550.tsv \
  --output docs/evidence/field-store-load-shift-00a45520/direct-call-memory-effects.jsonl

uv run --project . revenginstr-receiver-field-access-pairs \
  docs/evidence/field-store-load-shift-00a45520/parameter-stores.tsv \
  docs/evidence/field-store-load-shift-00a45520/parameter-loads.tsv \
  --program-id nfs-shift:SHIFT.exe \
  --memory-store-access-jsonl docs/evidence/field-store-load-shift-00a45520/memory-store-access.jsonl \
  --output docs/evidence/field-store-load-shift-00a45520/field-access-pairs.jsonl

uv run --project . revenginstr-receiver-field-store-load-audit \
  docs/evidence/field-store-load-shift-00a45520/field-access-pairs.jsonl \
  docs/evidence/field-store-load-shift-00a45520/function-pcode-cfg-v4.jsonl \
  --output docs/evidence/field-store-load-shift-00a45520/path-audit.jsonl

uv run --project . revenginstr-receiver-field-store-load-dominance-audit \
  docs/evidence/field-store-load-shift-00a45520/field-access-pairs.jsonl \
  docs/evidence/field-store-load-shift-00a45520/function-pcode-cfg-v4.jsonl \
  --memory-store-access-jsonl docs/evidence/field-store-load-shift-00a45520/memory-store-access.jsonl \
  --direct-call-memory-effect-jsonl docs/evidence/field-store-load-shift-00a45520/direct-call-memory-effects.jsonl \
  --output docs/evidence/field-store-load-shift-00a45520/dominance-audit.jsonl
```

## Artifact hashes

| Artifact | SHA-256 |
| --- | --- |
| Bounded caller/callee P-code | `934c673014b84b962e7b5574a9a41cd8752fef2b080f7d1f57ba36c7ecccbc61` |
| Callee P-code (`00a40550`) | `ca1e77856a40ba607ea18b48e45b851fa0e3da5a2cda848628d24af1e80f19ef` |
| Direct-call memory effects/1 | `7cf876edc1264270d73a1d486654837f3b066b85530d7a42d5ad8b666d638173` |
| Dominance audit/6–7 | `a7d0910b8336b87d8914cacc7f26311654af1cdda0044637bee5192482f70ca2` |
| Field access pairs/1 | `e88a8d4543fe962a9de041c087aef87551d9fdd1920f8f25606ef0bc31ae4baa` |
| Ghidra function P-code CFG/4 | `e8cc543b5ce9e542359eb6926e49ed980b603a12cb58a5ba6fd73cf1ecded2f6` |
| Caller P-code flow | `f468f2506089d2b2175b25311de2bafaf6f3acc5d89a9df9b31f6dd2ba9735c5` |
| Ghidra memory store access/1 | `235736d5a38e59c68fe8c86adaf13ba626d5d65acfaf3b923e6b6224fc1a1e86` |
| Ghidra parameter load field/1 | `facc794c48e31ea72ee031a25dc1f6bb80a68392efa91c9c4ecf740a1afb2972` |
| Ghidra parameter store field/1 | `5afcb2d296078813129b1b235b4cacab258cc7c8f4892be9a0d0f46e92d0e6ba` |
| Field store/load path audit/1–2 | `bac123b577708a75f1578c072dc5beef8137d1b344100d9259ea4a7ec9cab576` |
