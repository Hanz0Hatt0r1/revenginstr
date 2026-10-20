# Shift `0064bb70` interprocedural field store/load replay

This bounded x86-32 SHIFT replay was exported read-only from Ghidra 12.1.2
DEV with Java 21. The executable and Ghidra project are not included. Captured
P-code, CFG, argument-root, and memory facts are committed here for reproducible
analyzer replay.

## Result

The field-pair builder emits four exact parameter-0, offset-`0x84` pairs. Only
`STORE@0064bbf6` (time 160) to `LOAD@0064bd6c` (time 537) has a dominating
store. The path crosses eight direct calls and other writes, so both the
direct-call closure and the `/2` interprocedural audit keep its
`possible_intervening_memory_effect` status. The other three pairs have stores
that do not dominate their loads.

The caller-root exporter produced two exact parameter-offset mappings from
six scoped plans. At `0064bd7d`, callee `0064b8b0` parameter 0 maps to caller
parameter 0 at offset zero. The callee STORE at `0064b91f` is rooted at
parameter 0 plus `0x28`, four bytes; for the tracked `+0x84` four-byte field,
`/2` records this STORE as non-aliasing. The same callee also has an unresolved
STORE at `0064b8d2` and a `CALLIND` at `0064b90d`. The call therefore remains
`unknown_effect`, and the pair remains blocked. Other calls on the witness
have either write-free evidence for two call sites or unresolved effects and
possible aliasing stores. No unique candidate is produced.

The bounded capture contains the caller and eight direct callee flows. Across
the 29 caller call sites, closure statuses are: 7 explicit writes, 2
write-free callees, 9 unknown effects, 10 missing callee flows, and 1 indirect
call. The `/2` sidecar emits 116 pair/call rows: 64 unknown effects, 40
missing callee flows, 8 calls with no aliasing memory effect, and 4 indirect
calls. The callee flows were not recursively completed; nested calls without
their own evidence remain barriers. This replay demonstrates one exact
non-aliasing callee write fact while retaining the surrounding unknown effects.
It does not establish branch feasibility, runtime execution, or memory
reaching-definition/value flow.

An additional read-only Ghidra export records the two relevant `CALLIND`
target expressions. `CALLIND@0064bcda` (time 496, three arguments) loads its
target from `input:Stack[0x4]+0x28`. `CALLIND@0064b90d` (time 105, no arguments)
loads from `register+0x4c`. The exact root mapping at the call from `0064bb70`
to `0064b8b0` maps callee parameter 0 to caller parameter 0 + 0. The target
LOAD uses the same register base as the callee's rooted `STORE@0064b91f`, so
the loaded function-pointer storage is derived as caller parameter 0 +
`0x4c`. These expressions identify where the target is loaded, not its value;
both calls remain unresolved indirect effects and continue to block alias
filtering.

## Rebuild analyzer outputs

Run from the repository root with the project environment installed:

```sh
GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_indirect_call_evidence.sh \
  /home/pes/ghidra_projects nfs_shift_vulkan_runtime_20261018 SHIFT.exe \
  /tmp/callind-caller.jsonl 0064bb70
GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_indirect_call_evidence.sh \
  /home/pes/ghidra_projects nfs_shift_vulkan_runtime_20261018 SHIFT.exe \
  /tmp/callind-callee.jsonl 0064b8b0
cat /tmp/callind-caller.jsonl /tmp/callind-callee.jsonl > /tmp/indirect-call-evidence.jsonl
cmp /tmp/indirect-call-evidence.jsonl \
  docs/evidence/field-store-load-shift-0064bb70/indirect-call-evidence.jsonl

uv run --project . revenginstr-receiver-field-access-pairs \
  docs/evidence/field-store-load-shift-0064bb70/parameter-stores.tsv \
  docs/evidence/field-store-load-shift-0064bb70/parameter-loads.tsv \
  --program-id shift-fresh-6-region-0064bb70 \
  --memory-store-access-jsonl docs/evidence/field-store-load-shift-0064bb70/caller-memory-store-access.jsonl \
  --output docs/evidence/field-store-load-shift-0064bb70/field-access-pairs.jsonl

uv run --project . revenginstr-receiver-field-store-load-audit \
  docs/evidence/field-store-load-shift-0064bb70/field-access-pairs.jsonl \
  docs/evidence/field-store-load-shift-0064bb70/function-pcode-cfg-v4.jsonl \
  --output docs/evidence/field-store-load-shift-0064bb70/path-audit.jsonl

uv run --project . revenginstr-direct-call-memory-effect-closure \
  docs/evidence/field-store-load-shift-0064bb70/function-pcode-flow.tsv \
  --program-id shift-fresh-6-region-0064bb70 \
  --callee-flow 0064c6b0 docs/evidence/field-store-load-shift-0064bb70/callee-pcode-flow/0064c6b0.tsv \
  --callee-flow 008f3df0 docs/evidence/field-store-load-shift-0064bb70/callee-pcode-flow/008f3df0.tsv \
  --callee-flow 0064c5c0 docs/evidence/field-store-load-shift-0064bb70/callee-pcode-flow/0064c5c0.tsv \
  --callee-flow 0064c570 docs/evidence/field-store-load-shift-0064bb70/callee-pcode-flow/0064c570.tsv \
  --callee-flow 0064b8b0 docs/evidence/field-store-load-shift-0064bb70/callee-pcode-flow/0064b8b0.tsv \
  --callee-flow 00657d90 docs/evidence/field-store-load-shift-0064bb70/callee-pcode-flow/00657d90.tsv \
  --callee-flow 00457cc0 docs/evidence/field-store-load-shift-0064bb70/callee-pcode-flow/00457cc0.tsv \
  --callee-flow 0064bab0 docs/evidence/field-store-load-shift-0064bb70/callee-pcode-flow/0064bab0.tsv \
  --output docs/evidence/field-store-load-shift-0064bb70/direct-call-memory-effect-closure.jsonl

uv run --project . revenginstr-interprocedural-memory-effects \
  docs/evidence/field-store-load-shift-0064bb70/field-access-pairs.jsonl \
  docs/evidence/field-store-load-shift-0064bb70/function-pcode-cfg-v4.jsonl \
  docs/evidence/field-store-load-shift-0064bb70/closure-memory-store-access.jsonl \
  docs/evidence/field-store-load-shift-0064bb70/caller-offset-roots.tsv \
  --pcode-flow 0064bb70 docs/evidence/field-store-load-shift-0064bb70/function-pcode-flow.tsv \
  --pcode-flow 0064c6b0 docs/evidence/field-store-load-shift-0064bb70/callee-pcode-flow/0064c6b0.tsv \
  --pcode-flow 008f3df0 docs/evidence/field-store-load-shift-0064bb70/callee-pcode-flow/008f3df0.tsv \
  --pcode-flow 0064c5c0 docs/evidence/field-store-load-shift-0064bb70/callee-pcode-flow/0064c5c0.tsv \
  --pcode-flow 0064c570 docs/evidence/field-store-load-shift-0064bb70/callee-pcode-flow/0064c570.tsv \
  --pcode-flow 0064b8b0 docs/evidence/field-store-load-shift-0064bb70/callee-pcode-flow/0064b8b0.tsv \
  --pcode-flow 00657d90 docs/evidence/field-store-load-shift-0064bb70/callee-pcode-flow/00657d90.tsv \
  --pcode-flow 00457cc0 docs/evidence/field-store-load-shift-0064bb70/callee-pcode-flow/00457cc0.tsv \
  --pcode-flow 0064bab0 docs/evidence/field-store-load-shift-0064bb70/callee-pcode-flow/0064bab0.tsv \
  --output docs/evidence/field-store-load-shift-0064bb70/interprocedural-memory-effects.jsonl

uv run --project . revenginstr-receiver-field-store-load-dominance-audit \
  docs/evidence/field-store-load-shift-0064bb70/field-access-pairs.jsonl \
  docs/evidence/field-store-load-shift-0064bb70/function-pcode-cfg-v4.jsonl \
  --memory-store-access-jsonl docs/evidence/field-store-load-shift-0064bb70/closure-memory-store-access.jsonl \
  --direct-call-memory-effect-closure-jsonl docs/evidence/field-store-load-shift-0064bb70/direct-call-memory-effect-closure.jsonl \
  --output docs/evidence/field-store-load-shift-0064bb70/dominance-with-call-closure.jsonl

uv run --project . revenginstr-receiver-field-store-load-dominance-audit \
  docs/evidence/field-store-load-shift-0064bb70/field-access-pairs.jsonl \
  docs/evidence/field-store-load-shift-0064bb70/function-pcode-cfg-v4.jsonl \
  --memory-store-access-jsonl docs/evidence/field-store-load-shift-0064bb70/closure-memory-store-access.jsonl \
  --interprocedural-memory-effect-jsonl docs/evidence/field-store-load-shift-0064bb70/interprocedural-memory-effects.jsonl \
  --output docs/evidence/field-store-load-shift-0064bb70/dominance-with-interprocedural-effects.jsonl
```

## Artifact hashes

| Artifact | SHA-256 |
| --- | --- |
| Caller argument plan TSV | `5ee147a23e023fe9516d6097eea27af48ec6591fc92fc9743a9bb0379b3b3a02` |
| Caller argument subtrees TSV | `f6d95eee9b2ccd92962126b7d3755c4b92f740b24b50e092fded1f917f560abd` |
| Caller memory-store access/1 | `8bd9fdcf177ff7331816c608bf220ea4bdd5e30d4f01e5155b4414f0c159fd93` |
| Caller offset roots TSV | `f51e70d37e75c656dd24ddc8effe44c5a26265c53d775da956536681cd2fbd1d` |
| Closure memory-store access/1 | `2f2235fdc34344d8b90fb53e9930680aeea37e382d94f56adad0e0b192048784` |
| Direct-call closure/1 | `36c499622b678d631979cc471a038b94e9048a0a7cfe3e90dd1c9a15621094e0` |
| Dominance with closure | `fd52376f6b8099f0cbd20f946ac6291a55fd63765df35ad17beadccdc7d047f2` |
| Dominance with interprocedural effects | `f2a7a927fc2b92beae48e68063de128e636905e0a523ecc8f1c5e9d36315ce06` |
| Field access pairs | `ce047fe2f84cb35a2c6d01b8f2c8d71a6d1ceae425b9fb7a1ceb266c9e8d1417` |
| Ghidra function P-code CFG/4 | `4dfb4ff6efdcbb6298492b8c35530dff8ef67f16cb3301026514f71a707c7e45` |
| Caller Ghidra function P-code flow/1 | `81cb98a80b172acba9b2328953bb49808bca6174b5c90c4761a99bc1923f00f3` |
| Interprocedural memory effects/2 | `d62d19c36a7c810dd0b3071f1ce2e044d71a961b8a4426e08208d5f16facbd94` |
| Parameter load field/1 | `b1ea8270e3665df9433f0735c0dd6df8f19c5c52fdd0657868d6359bd51f0dec` |
| Parameter store field/1 | `02327af81026a0169362cd1756125cafa089be59a9564c74a7b4c7f1aff5064a` |
| Field store/load path audit/2 | `6852e2a597fe7b948b33cf8df72602dd0b1351a9eabcaa4e0bc9f42e1337c590` |
| Ghidra indirect-call target evidence/1 | `85e120d14dc94221b0e2fe458baa7755d9aa229969699afd28b54e50358ffebe` |
| Callee flow `00457cc0` | `ae8f64b9ac91bb9a59240d8f53d6b063059f51611199b6fcfb6ff8a98552b975` |
| Callee flow `0064b8b0` | `41e5a8cab45d76a689bd8d477b0e01b1ea476afc008aac065dd98383b5c07332` |
| Callee flow `0064bab0` | `fcb0f6a8587903b1d51452b6b3c32752b7004ed405ddb506e178154d663e6057` |
| Callee flow `0064c570` | `7c4d9810b384793c0a07fc4f33d08b3eca8d5406c340e526c19990e637df0666` |
| Callee flow `0064c5c0` | `9729c9787579bc13c36e31927ddf0bc6d4b9e79cb5e83b91abf2e055f2af27fe` |
| Callee flow `0064c6b0` | `25c229bc49044f366ccc910add4e12db8b8ec12f6c69691c575c66275f9b857c` |
| Callee flow `00657d90` | `86c29cecb3a62e6b304467812ffba2cf00135e88f3d2e028fec90b98c386bae3` |
| Callee flow `008f3df0` | `a69bd1874f52d97057cbc14496fba48e98c9f612cb0c3b78706249e8ce649a12` |
