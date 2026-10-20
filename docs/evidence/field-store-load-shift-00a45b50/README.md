# Shift `00a45b50` field store/load replay

This x86-32 replay uses a read-only capture from the existing Ghidra project
for `SHIFT.exe` (Ghidra 12.1.2 DEV). The program bytes have SHA-256
`eca479aa2d8dbb88bc55709d91ae5c7159ae1b00fc9555d6701000c26de8aee1`; the
executable and Ghidra project are not committed. The committed exports are
sufficient to rebuild the RevEngInstr outputs.

## Result

The fresh exporters produced one parameter store, six parameter loads, and
eight general STORE facts, seven rooted at exact parameter-plus-offset
locations. The pair builder emitted nine field pairs. The path audit reported
one `candidate_path_compatible`, three `intervening_store_or_call`, and five
`no_cfg_path` rows.

The CFG/4, parameter-field, and memory-store exports were recaptured
read-only from the same saved project. An older consumer memory-store export
referenced synthetic CAST sequence IDs absent from the fresh CFG; the recapture
passed the analyzer's exact operation-reference checks without weakening them.

The CFG/4 dominance replay emitted two `unique_cfg_store_candidate` rows, one
`possible_intervening_memory_effect`, and six `store_not_dominating_load` rows:

| Store → load | Evidence | Result |
| --- | --- | --- |
| `STORE@00a45b69` (time 33, `param1+0x4`, value from param 3) → `LOAD@00a45b75` (time 44) | CFG/4 and rooted STORE facts; calls follow the load | `/6` `unique_cfg_store_candidate` |
| `STORE@00a45b75` (time 46, `param1+0x4`, source value unresolved) → `LOAD@00a45b78` (time 57) | CFG/4 and rooted STORE facts | `/7` `unique_cfg_store_candidate` |
| `STORE@00a45b69` (time 33) → `LOAD@00a45b78` (time 57) | The second same-field STORE at time 46 intervenes | `/6` `possible_intervening_memory_effect` |

The second positive row exercises memory-only store provenance without
claiming a source parameter for its value. The two direct calls at times 98
and 175 are explicit memory writes, but both occur after the two positive
load witnesses. This is structural evidence only: it does not establish
runtime execution or a memory reaching definition.

## Rebuild Ghidra exports

Run from the repository root against the already imported, read-only project:

```sh
GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_function_pcode_cfg.sh \
  /home/pes/ghidra_projects nfs_shift_vulkan_runtime_20261018 SHIFT.exe \
  docs/evidence/field-store-load-shift-00a45b50/function-pcode-cfg-v4.jsonl \
  nfs-shift:SHIFT.exe 00a45b50 --indirect-effect-links

GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_parameter_store_field.sh \
  /home/pes/ghidra_projects nfs_shift_vulkan_runtime_20261018 SHIFT.exe \
  00a45b50 docs/evidence/field-store-load-shift-00a45b50/parameter-stores.tsv \
  --load-output docs/evidence/field-store-load-shift-00a45b50/parameter-loads.tsv \
  --memory-access-output docs/evidence/field-store-load-shift-00a45b50/memory-store-access.jsonl \
  --program-id nfs-shift:SHIFT.exe
```

`bounded-pcode.tsv` is the frozen caller/callee P-code capture. Its rows are
partitioned into the included caller and callee TSVs for rebuilding the direct
call effects.

## Rebuild analyzer outputs

Run from the repository root with the project environment installed:

```sh
uv run --project . revenginstr-direct-call-memory-effects \
  docs/evidence/field-store-load-shift-00a45b50/function-pcode-flow.tsv \
  --program-id nfs-shift:SHIFT.exe \
  --callee-flow 00a459f0 docs/evidence/field-store-load-shift-00a45b50/callee-pcode-flow/00a459f0.tsv \
  --output docs/evidence/field-store-load-shift-00a45b50/direct-call-memory-effects.jsonl

uv run --project . revenginstr-receiver-field-access-pairs \
  docs/evidence/field-store-load-shift-00a45b50/parameter-stores.tsv \
  docs/evidence/field-store-load-shift-00a45b50/parameter-loads.tsv \
  --program-id nfs-shift:SHIFT.exe \
  --memory-store-access-jsonl docs/evidence/field-store-load-shift-00a45b50/memory-store-access.jsonl \
  --output docs/evidence/field-store-load-shift-00a45b50/field-access-pairs.jsonl

uv run --project . revenginstr-receiver-field-store-load-audit \
  docs/evidence/field-store-load-shift-00a45b50/field-access-pairs.jsonl \
  docs/evidence/field-store-load-shift-00a45b50/function-pcode-cfg-v4.jsonl \
  --output docs/evidence/field-store-load-shift-00a45b50/path-audit.jsonl

uv run --project . revenginstr-receiver-field-store-load-dominance-audit \
  docs/evidence/field-store-load-shift-00a45b50/field-access-pairs.jsonl \
  docs/evidence/field-store-load-shift-00a45b50/function-pcode-cfg-v4.jsonl \
  --memory-store-access-jsonl docs/evidence/field-store-load-shift-00a45b50/memory-store-access.jsonl \
  --direct-call-memory-effect-jsonl docs/evidence/field-store-load-shift-00a45b50/direct-call-memory-effects.jsonl \
  --output docs/evidence/field-store-load-shift-00a45b50/dominance-audit.jsonl
```

## Artifact hashes

| Artifact | SHA-256 |
| --- | --- |
| Bounded caller/callee P-code | `5da44d69a7fde99ca622eec018f5e6bdbbc7fd74d604a47a1f6f3bf6518cbf2b` |
| Callee P-code (`00a459f0`) | `7c1ef4f0ec6fdbbd347f7604d4048bcaf3cf6fff4366a0d6402117f8073edac0` |
| Direct-call memory effects/1 | `a249bb57f063122952676e30c130095ab99239852594739e2378705da72e6746` |
| Dominance audit/6–7 | `8bf1a63c09b033ef578bc26be7cb02d33e30b8189915a87f5460b0cefa7c6c21` |
| Field access pairs/1 | `fac3216d9c181c40979ca5648aaf27e6efee71cb2e5edbf06f323b21a8670796` |
| Ghidra function P-code CFG/4 | `228cd4477fd3f17b564ff558fe479a5f042e2db4bc1891d55411bbc157e8a55b` |
| Caller P-code flow | `1a190430e17c2132c03833707dbe52acd24fac5c3d41a81d87154ed5dba75a93` |
| Ghidra memory store access/1 | `965bb02a4336d7809146349e4ec617599010aeafe2197ee4c0ee7b86d3b4ba34` |
| Ghidra parameter load field/1 | `fc7cf6b37a21c8859e1e95c67aad6c9a5d052838d55300b4d05606890478ed5a` |
| Ghidra parameter store field/1 | `57965828f8aac7516e381fe8d578918dd9b337a85e619fa0eaef54024f32bdc6` |
| Field store/load path audit/1–2 | `f27ab263efd120c0f7b151065c97ae4184757b04c3483f15fd86578eb86c29c4` |
