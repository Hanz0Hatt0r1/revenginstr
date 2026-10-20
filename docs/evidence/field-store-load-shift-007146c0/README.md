# Shift `007146c0` field store/load replay

This bounded x86-32 SHIFT replay uses a read-only Ghidra 12.1.2 DEV project
with Java 21. The executable and Ghidra project are not included; the captured
parameter, memory, P-code, and CFG exports are committed here so the analyzer
results can be regenerated.

## Result

The field-pair builder joined one parameter-0 load at `00714810`, offset
`0x15c`, with an exact destination-only memory STORE at `007147f8`, P-code time
415, also rooted at parameter 0 plus `0x15c`. Its width is four bytes. The
STORE has no recovered value-formal source (`source_parameter_index` is null).
The separate `ParameterStoreField/1` row at `0071475c`, offset `0x148`, does
not form this pair.

`FieldStoreLoadPathAudit/2` returns `candidate_path_compatible` with CFG blocks
`[5, 6]`. `FieldStoreLoadDominanceAudit/7` returns
`unique_cfg_store_candidate`: the STORE dominates the LOAD, and no write or
call lies after that STORE and before the LOAD on the witness path.

The function has ten direct calls. Neither the direct-call closure nor the
interprocedural audit received callee flows, so each records
`missing_callee_flow`; the empty `/2` caller-root file makes no alias claim.
The calls have P-code times 34 through 412, before the tracked STORE at 415.
The call at `007147f3` (time 412) is in the same CFG block, before the STORE.
Both audits retain the unique candidate because unresolved calls before the
tracked STORE are outside the STORE-to-LOAD witness. This is a static CFG
candidate, not proof of branch feasibility, runtime execution, or memory
reaching-definition/value flow.

## Rebuild analyzer outputs

Run from the repository root with the project environment installed:

```sh
uv run --project . revenginstr-receiver-field-access-pairs \
  docs/evidence/field-store-load-shift-007146c0/parameter-stores.tsv \
  docs/evidence/field-store-load-shift-007146c0/parameter-loads.tsv \
  --program-id shift-fresh-6-region-007146c0 \
  --memory-store-access-jsonl docs/evidence/field-store-load-shift-007146c0/memory-store-access.jsonl \
  --output docs/evidence/field-store-load-shift-007146c0/field-access-pairs.jsonl

uv run --project . revenginstr-receiver-field-store-load-audit \
  docs/evidence/field-store-load-shift-007146c0/field-access-pairs.jsonl \
  docs/evidence/field-store-load-shift-007146c0/function-pcode-cfg-v4.jsonl \
  --output docs/evidence/field-store-load-shift-007146c0/path-audit.jsonl

uv run --project . revenginstr-direct-call-memory-effect-closure \
  docs/evidence/field-store-load-shift-007146c0/function-pcode-flow.tsv \
  --program-id shift-fresh-6-region-007146c0 \
  --output docs/evidence/field-store-load-shift-007146c0/direct-call-memory-effect-closure.jsonl

uv run --project . revenginstr-interprocedural-memory-effects \
  docs/evidence/field-store-load-shift-007146c0/field-access-pairs.jsonl \
  docs/evidence/field-store-load-shift-007146c0/function-pcode-cfg-v4.jsonl \
  docs/evidence/field-store-load-shift-007146c0/memory-store-access.jsonl \
  docs/evidence/field-store-load-shift-007146c0/caller-offset-roots.tsv \
  --pcode-flow 007146c0 docs/evidence/field-store-load-shift-007146c0/function-pcode-flow.tsv \
  --output docs/evidence/field-store-load-shift-007146c0/interprocedural-memory-effects.jsonl

uv run --project . revenginstr-receiver-field-store-load-dominance-audit \
  docs/evidence/field-store-load-shift-007146c0/field-access-pairs.jsonl \
  docs/evidence/field-store-load-shift-007146c0/function-pcode-cfg-v4.jsonl \
  --memory-store-access-jsonl docs/evidence/field-store-load-shift-007146c0/memory-store-access.jsonl \
  --direct-call-memory-effect-closure-jsonl docs/evidence/field-store-load-shift-007146c0/direct-call-memory-effect-closure.jsonl \
  --output docs/evidence/field-store-load-shift-007146c0/dominance-with-call-closure.jsonl

uv run --project . revenginstr-receiver-field-store-load-dominance-audit \
  docs/evidence/field-store-load-shift-007146c0/field-access-pairs.jsonl \
  docs/evidence/field-store-load-shift-007146c0/function-pcode-cfg-v4.jsonl \
  --memory-store-access-jsonl docs/evidence/field-store-load-shift-007146c0/memory-store-access.jsonl \
  --interprocedural-memory-effect-jsonl docs/evidence/field-store-load-shift-007146c0/interprocedural-memory-effects.jsonl \
  --output docs/evidence/field-store-load-shift-007146c0/dominance-with-interprocedural-effects.jsonl
```

The committed caller-root TSV contains only its `/2` header: no caller roots
were exported because no callee flows were supplied. The call-effect files
therefore document incomplete evidence rather than callee behavior.

## Artifact hashes

| Artifact | SHA-256 |
| --- | --- |
| Caller offset roots TSV | `84476b9f55baf27f9d798b9d2cb6915becc88b0bcf68266cd9f8bc077a2c373a` |
| Direct-call memory-effect closure | `d5375fa418a876d720456e50c0c4781186208028e2d74154e2488e5597939d6c` |
| Dominance with call closure | `ad3d5eb543f334f626da498361bc9ff4f7fe55f27f8b1ba7b42b7f0a406b9235` |
| Dominance with interprocedural effects | `74cc5e0ea935d4cdc8048475ded4f5d321ddb280a6cd51c4a268de208ff36fc0` |
| Field access pairs | `ea6e8d3dfad3661b5ccfb2ee149fc6aaeb5ce26a55e7ecf5a1bf32b1eebe2993` |
| Ghidra function P-code CFG/4 | `6593e4a1d41c997613a768b3c746bb3cd70ea2591c36aa338ce3602575a9c899` |
| Ghidra function P-code flow/1 | `bd448394e3ce9af916d8335b0f0ec88345e1abd2d8148a33515603b1e5c5e947` |
| Interprocedural memory effects/2 | `00ea68de2ceea4a64c230ad403470319cdf2010ed9d01f4c1ece3c8f6ead8e35` |
| Ghidra memory store access/1 | `17f4e09ce670975ee89d56231ed848f0294c554409cd4a5f2033fa39688e4520` |
| Ghidra parameter load field/1 | `9e549fe53777f1e80641000ce23d14d2ea43261c4ad6bcb0b912d064896f860a` |
| Ghidra parameter store field/1 | `8a650323330d96fcb11937d94f66749afe465c10f3cdb4040a3eaf268efede89` |
| Field store/load path audit/2 | `d979c0abddc22d07b6e856df98f3dc615ce8b9fe1b9aa6993acaacc2be4aeb45` |
