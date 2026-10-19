# CFG/5 seeded-callee extension

**Capture date:** 2026-10-20. **Target:** retail `SHIFT.exe`, SHA-256
`eca479aa2d8dbb88bc55709d91ae5c7159ae1b00fc9555d6701000c26de8aee1`.
Exports use Ghidra 12.1.2 with Java 21.0.12.1 against the saved project in
read-only, analysis-disabled mode.

## Exact callee evidence

The prior interprocedural replay included the caller and 97 selected closure
flows. The closure flow for `006642a0` contains a direct call to `006642a5`, but
the target's body was not present in that selection. Its separately retained
18-row P-code flow and CFG/5 were added. That function calls `00664140` at
`006642b8` and `00900fb3` at `006642c2`. The existing selection already
contains `00900fb3`, so the remaining new direct target was exported from the
saved project as a 33-row P-code flow with a one-block CFG/5.

The `006642a5` flow passes a cast of global address `00bfc728` to
`00664140` at `006642b8`. The `00664140` memory-store export records nine stores
rooted at its parameter 0, at byte offsets `0x0`, `0x4`, `0x3c`, `0x40`,
`0x44`, `0x48`, `0x4c`, `0x64`, and `0x68`. These facts identify the callee's
write locations relative to its formal parameter; they do not prove whether
that global object can alias any caller field tracked by `/6`.

`00664140` also makes five direct calls whose bodies are absent from this
bounded input: `0066f5b0`, `007f6690`, `0066f510`, `0064ec60`, and `0066e0e0`.
They remain explicit unknown-effect barriers. No runtime execution or alias
claim is inferred from this static replay.

## Refreshed effect replay

The flow selection now contains 99 callee entries, adding `006642a5` and
`00664140` to the previous 97. The CFG/5 input has 103 function records, and
the full-closure memory-store input has 423 records after adding the nine
`00664140` stores. The interprocedural exporter produced 670 effect rows; 40
pair/call closures now reach `00664140`, and those closures contain 95 functions
instead of 93 before the seeded-target additions.

The `/6` audit still reports four
`possible_intervening_memory_effect` rows and one
`unique_cfg_store_candidate`. The new callee improves exact closure evidence,
but it does not resolve whether its global object or five nested call targets
can affect the tracked field pairs.

## Retained artifacts

- [`field20-00664140-pcode-flow.tsv`](field20-00664140-pcode-flow.tsv): 33 exact P-code rows.
- [`field20-00664140-pcode-cfg-v5.jsonl`](field20-00664140-pcode-cfg-v5.jsonl): exact one-function CFG/5.
- [`field20-00664140-memory-store-access.jsonl`](field20-00664140-memory-store-access.jsonl): nine store facts.
- [`interprocedural-flow-input-entries-cfg5-followup.txt`](interprocedural-flow-input-entries-cfg5-followup.txt): all 99 selected callee entries.
- [`closure-function-pcode-cfg-v5-with-006642a5-00664140.jsonl`](closure-function-pcode-cfg-v5-with-006642a5-00664140.jsonl): 103 CFG/5 records.
- [`memory-store-access-full-closure-scope-with-00664140.jsonl`](memory-store-access-full-closure-scope-with-00664140.jsonl): 423 memory-store facts.
- [`interprocedural-memory-effects-v2-cfg5-with-006642a5-00664140.jsonl`](interprocedural-memory-effects-v2-cfg5-with-006642a5-00664140.jsonl): refreshed 670-row effect sidecar.
- [`field-store-load-dominance-v6-cfg5-with-006642a5-00664140.jsonl`](field-store-load-dominance-v6-cfg5-with-006642a5-00664140.jsonl): refreshed five-pair audit.

The two RevEngInstr CLIs consumed these pinned inputs to build the effect and
audit sidecars. The original CFG/5 capture remains available in
[`cfg-v5-entry-block-replay.md`](cfg-v5-entry-block-replay.md); this note records
the exact additions and resulting closure.
