# NFS SHIFT receiver-field screening, 2026-10-19

This replay continues the receiver-field and memory-effect work using the
retail `SHIFT.exe` export and the bounded batch exporter in RevEngInstr commit
[`db5fbe9`](https://github.com/Hanz0Hatt0r1/revenginstr/commit/db5fbe9fb2fed92ce1d856bb528a8f879c2b29c6).
The executable itself is not included. Its SHA-256 is
`eca479aa2d8dbb88bc55709d91ae5c7159ae1b00fc9555d6701000c26de8aee1`.
Function and direct-call indexes used only to choose targets are pinned in
each `selection-source.json`; the executable's High-P-code supplies all
memory facts. The [manifest](manifest.json) pins every retained artifact by
byte count, row count where applicable, and SHA-256.
The local executable path in the retained selection manifests is normalized
to `SHIFT.exe`; the executable hash is unchanged. Ghidra ran with analysis
disabled for all evidence exports. The `006642a5` replay seeded the missing
function only in a disposable project copy; its CFG export then opened that
copy read-only.

## Screens

Each screen uses entries in `00401000`–`004fffff` that are non-external,
non-thunk direct-call callers. Scan25 required at least one explicit
`param_n` and a 40–800-byte function body, then sampled 100 address-ordered
quantiles from 2,374 eligible functions. Scan26 required at least two
explicit parameters and a 100–800-byte body, excluded scan25's selected
entries, and sampled 256 of 561 eligible functions. Scan27 exported all 305
remaining functions in that scan26 population in two batches (256 and 49).
The inventories and call-edge index only selected addresses; no corpus memory
label was consumed.

| Screen | Functions | Parameter-field stores | Parameter loads | General STORE facts | Exact pairs | `/6` results |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| [scan25](scan25/) | 100 | 8 | 271 | 282 | 0 | No audit |
| [scan26](scan26/) | 256 | 34 | 965 | 951 | 8 | 6 possible effects; 2 non-dominating stores |
| [scan27](scan27/) | 305 | 64 | 1,302 | 1,180 | 16 | 5 possible effects; 11 non-dominating stores |
| [scan28](scan28/) | 256 | 6 | 583 | 848 | 1 | 1 non-dominating store |
| [scan29](scan29/) | 256 | 8 | 689 | 991 | 5 | 1 unique candidate after focused call-effect replay; 3 possible effects; 1 non-dominating store |
| [scan30](scan30/) | 256 | 12 | 543 | 1,040 | 4 | 4 non-dominating stores |
| [scan31](scan31/) | 256 | 7 | 598 | 572 | 7 | 7 non-dominating stores |
| [scan32](scan32/) | 256 | 12 | 566 | 770 | 3 | 1 possible effect; 2 non-dominating stores |
| [scan33](scan33/) | 256 | 12 | 617 | 688 | 4 | 1 possible effect; 3 non-dominating stores |
| [scan34](scan34/) | 177 | 2 | 551 | 494 | 1 | 1 non-dominating store |
| [scan35](scan35/) | 4 | 0 | 0 | 0 | 0 | No pairs; `/6` not run |
| [scan36](scan36/) | 295 | 77 | 1,907 | 1,748 | 14 | 14 non-dominating stores |
| [scan37](scan37/) | 161 | 26 | 2,869 | 4,152 | 39 | 33 non-dominating stores; 5 possible effects before focused replay; 1 unique candidate |

Scan28 sampled 256 midpoint quantiles from the 1,713 previously unselected
functions with at least one explicit parameter and a 40–800-byte body. Its
sole pair in `004301a0` loads at `004301a9` before the paired store at
`004301b3`, so the store does not dominate the load and no `/5` replay is
eligible.

Scan29 sampled 256 midpoint quantiles from the 1,457 remaining functions in
the same broad population. Its five pairs are in `00458170` and `004d90b0`.
The initial `/6` screen found four possible effects in `00458170` and one
non-dominating store in `004d90b0`. The focused replay in
[`replay-00458170`](scan29/replay-00458170/) followed the first pair's call at
`0045818a` to `0067cbc0`. The exact caller root is parameter 0 plus `0xc`; the
callee's complete three-operation flow contains only `COPY`, `CAST`, and
`RETURN`, so the interprocedural audit classifies that call as
`no_aliasing_memory_effect`. The `/6` replay then marks the store at
`00458187` and load at `004581a7` as one `unique_cfg_store_candidate`. The
other three pairs in `00458170` remain possible because unresolved memory
writes and calls still lie on their paths. This is structural evidence only;
it does not establish feasible execution or runtime value flow.

The focused replay also validates the generic `/5` consumer against these
hash-pinned facts. The retained CFG/4 is projected to CFG/3 by
[`project_ghidra_function_pcode_cfg_v4_to_v3.py`](../../../../scripts/project_ghidra_function_pcode_cfg_v4_to_v3.py),
which changes only the format tag and removes each operation's
`indirect_effect_link`; blocks, operation identities, and memory metadata are
preserved. The resulting CFG/3 projection, interprocedural effect `/1`, and
dominance audit `/5` are retained in the focused replay directory. The `/5`
audit reports one `unique_cfg_store_candidate` for store `00458187` and load
`004581a7` at offset `0x4`; the other three pairs remain
`possible_intervening_memory_effect`. This confirms a positive consumer path
without promoting branch feasibility, runtime value flow, or type identity.

Scans30–34 exhausted the remaining 1,201 functions in the same one-or-more-
`param_n` population: four midpoint-quantile batches of 256 and a final batch
of 177. They produced nineteen exact pairs. Seventeen stores do not dominate
their paired loads. The other two remain possible because a direct call's
memory effect could not be resolved; the focused replays are retained under
[`scan32/replay-004f8fe0`](scan32/replay-004f8fe0/) and
[`scan33/replay-0046f8d0`](scan33/replay-0046f8d0/). No new unique candidate
was established, so scan29 remains the only unique structural candidate in
scans25–34.

In scan32, the remaining pair in `004f8fe0` crosses a call at `004f9010` to
`0062e1a0`. The bounded callee closure reaches an indirect call and an unknown
effect; the pair therefore stays `possible_intervening_memory_effect`. In
scan33, the pair in `0046f8d0` crosses a call at `0046f909` to `0063ad50`.
Only one exact caller argument root is recovered, while the callee contains
an unresolved STORE destination. The interprocedural call remains
`unknown_effect`, and the pair remains possible. Neither replay promotes an
aliasing or safe-to-filter claim.

Scan35 exhaustively screened the four remaining direct-call callers whose
signature has `this` but no explicit `param_n`, with 40–800-byte bodies. The
High-P-code exporter processed all four functions and emitted no
parameter-rooted field stores, parameter-rooted field loads, or STORE facts;
there are no pairs to audit. This is a bounded negative result for this
population, not a claim about other access forms or runtime behavior.

Scan36 exhaustively screened the 295 functions with at least one explicit
`param_n`, 40–800-byte bodies, and no direct-call caller row in the pinned
call-edge index. It produced 77 field stores, 1,907 field loads, 1,748
general STORE facts, and fourteen exact pairs across seven functions. All
fourteen stores fail to dominate their paired loads; no `/5` replay is
eligible. The index labels these as non-direct-call callers, but that does not
prove they are called only indirectly.

Scan37 exhaustively screened all 161 explicit-parameter functions with bodies
larger than 800 bytes: 159 have outgoing direct-call rows and two do not. It
produced 39 exact pairs in `0041dd40` and `004e0f20`. Thirty-three stores do
not dominate their loads. In `004e0f20`, store `004e15c2` and load `004e15d4`
at offset `0x6c` form one unique structural candidate. Five pairs in
`0041dd40` entered focused replay; one became unique and four remain possible
because indirect calls, missing CFG, and an unavailable direct target remain
barriers.

The focused replay in
[`scan37/replay-0041dd40`](scan37/replay-0041dd40/) follows the direct-call
closure from `0041dd40`. It supplies all 97 P-code flows reachable from exact
CALL operations and CFG/4 for 95 of those functions. CFG export skips
`006642a0` because no entry block exists and excludes `0090e864` because its
decompiler graph has multiple entry blocks; both gaps are listed in
`closure-cfg-skipped-functions.tsv`. Three function-index edges are not
reachable from the captured P-code calls and are excluded. The expanded CFG/4
removes source-linked `INDIRECT` markers, but 22 reachable `CALLIND` operations
across 13 functions still block four pairs. The closure also reaches a direct
CALL target `006642a5` absent from the pinned function inventory. The full
closure replay keeps the same four pairs possible and the fifth pair unique;
it does not promote any alias or runtime value-flow claim. A follow-up seeded
replay now captures the exact function body and CFG for that target; see
[`field20-006642a5-replay.md`](scan37/replay-0041dd40/field20-006642a5-replay.md).

A follow-up CFG/5 export now retains the caller and all 100 functions from the
captured closure flow selection, including the empty-root graph at `006642a0` and both
entry roots `[0, 1]` at `0090e864`. It skips no functions. The raw export and
replay details are in
[`cfg-v5-entry-block-replay.md`](scan37/replay-0041dd40/cfg-v5-entry-block-replay.md).
The rebuilt interprocedural sidecar removes `MISSING_CFG` from 40 effect rows,
but their `CALLIND` and `STORE` barriers remain. The `/6` results stay at four
possible effects and one unique candidate, matching the earlier CFG/4 statuses.
The two boundary functions are not field-pair candidates in this replay.

`closure-pointer-provenance.jsonl` applies `PointerProvenance/1` to the same
98 flows, 22 exact `CALLIND` rows, and retained v2 parameter-root mappings.
Among the 22 target records, six stop at memory-read anchors, thirteen at
call barriers, and three are ambiguous. None resolves to an exact function
entry through `PointerProvenance/1` alone, so its output does not reduce the
call-effect barriers.

The read-only receiver-type export also matched all 22 sites across 13
functions, with no failed functions or count mismatches. Five sites have no
receiver operand; the remaining type labels are generic `int`, `undefined4`,
or `size_t`, and the sole recovered pointee is `undefined4`. This adds no
class or target identity evidence and does not narrow the call-effect set.

A separate read-only static-data review resolves two of those six memory-read
anchors. The `0064a0c0` and `0064a100` wrappers receive the result of
`0064a010` at all four direct call sites in `0088d1d0`. `0064a010` returns
`0x00bfa9b0` on both initialization paths. Its constructor stores the result
of the `006642a0` helper in that object's first field; the helper's jump into
the now fully exported function `006642a5` returns `0x00bfc728`. Constructor
`00664140` sets that singleton's vtable pointer to `0x00af08a0`, whose slot at
`+0x30` (`0x00af08d0`) contains `0x00664a10`. This makes `00664a10` the
evidence-backed static target for `CALLIND` at `0064a0ce` and `0064a10e`.
The caller and return evidence is in
[`caller-arguments-closure.tsv`](scan37/replay-0041dd40/caller-arguments-closure.tsv),
[`closure-pcode-flow.tsv`](scan37/replay-0041dd40/closure-pcode-flow.tsv),
[`closure-static-return-address-refs.jsonl`](scan37/replay-0041dd40/closure-static-return-address-refs.jsonl),
and [`closure-static-return-address-metadata.jsonl`](scan37/replay-0041dd40/closure-static-return-address-metadata.jsonl).
The implementation exports are
[`closure-static-return-function-instructions.jsonl`](scan37/replay-0041dd40/closure-static-return-function-instructions.jsonl),
[`closure-static-object-constructor-instructions.jsonl`](scan37/replay-0041dd40/closure-static-object-constructor-instructions.jsonl),
[`closure-static-interface-factory-instructions.jsonl`](scan37/replay-0041dd40/closure-static-interface-factory-instructions.jsonl),
[`closure-interface-factory-tail-slice.jsonl`](scan37/replay-0041dd40/closure-interface-factory-tail-slice.jsonl),
[`closure-secondary-singleton-constructor-instructions.jsonl`](scan37/replay-0041dd40/closure-secondary-singleton-constructor-instructions.jsonl),
[`closure-secondary-singleton-vtable-metadata.jsonl`](scan37/replay-0041dd40/closure-secondary-singleton-vtable-metadata.jsonl),
[`closure-secondary-singleton-references.jsonl`](scan37/replay-0041dd40/closure-secondary-singleton-references.jsonl),
and [`closure-first-pair-target-instructions.jsonl`](scan37/replay-0041dd40/closure-first-pair-target-instructions.jsonl).
The seeded 43-byte function `006642a5` now has a complete 18-row P-code flow
and CFG/5 export; see [`field20-006642a5-replay.md`](scan37/replay-0041dd40/field20-006642a5-replay.md).
Following the recovered target `00664a10` adds its two
internal `CALLIND` sites, `00664a4f` and `00664a83`. The targeted
[`P-code flow`](scan37/replay-0041dd40/target-function-00664a10-flow.tsv),
[`CALLIND evidence`](scan37/replay-0041dd40/target-function-00664a10-callind-evidence.jsonl),
and [`PointerProvenance/1` output](scan37/replay-0041dd40/target-function-00664a10-pointer-provenance.jsonl)
show the two targets as memory-read anchors when considered by provenance
alone. A separate review of the same pinned executable resolves those two
sites through the `0x00af0860` vtable: `00664a4f` calls `0x009ec700` at slot
`0`, and `00664a83` calls `0x009d1880` at slot `0x34`. Both are leaf field
readers for the observed collection construction path. The exact raw table
entries, constructor/append chain, target instruction bytes, and limits are
recorded in
[`manual-static-vtable-review.md`](scan37/replay-0041dd40/manual-static-vtable-review.md).
`00664a10` returns the second reader's runtime field value, so it still does
not identify the runtime receiver used by later calls in `006657e0` and
`00665820`. Static vtable evidence now gives bounded candidate sets for the
first-level cached-field calls and partial candidate sets for the two calls on
their returned objects. This manual review does not change the `/6` statuses
or establish that runtime memory cannot be overwritten.
The generic [`IndirectCallPointerSlot/1` replay](scan37/replay-0041dd40/indirect-call-pointer-slots.jsonl)
joins all 22 closure `CALLIND` sites to the exact pointer-provenance rows. Six
have a single aligned constant-offset pointer-slot shape. The four downstream
sites are `006657ed` (`+0x30`), `00665801` (`+0x8`), `0066582d` (`+0x34`), and
`00665841` (`+0xc`). These offsets describe loads through runtime-derived
pointer anchors; they do not associate those anchors with a specific table or
resolve a function entry by themselves. The vtable candidate replay below
joins the two cached-field calls to five constructor-observed vtables; the
other 16 sites are not a single resolved constant-offset target load.

The read-only Ghidra xrefs in
[`anchor-address-references.jsonl`](scan37/replay-0041dd40/anchor-address-references.jsonl)
show that `006657e0` and `00665820` are called directly from wrappers
`0064a0c0` and `0064a100`; those wrappers first call the collection lookup,
which returns the runtime field at `+0x20`. The xrefs to table `0x00af0860`
include its writes in `0066ee90` and `00663f50`, plus `0043c792`. The latter is
reached from the cleanup path `0066efc0` and is not another factory. This
is now complemented by a read-only High-P-code capture of ten exact functions.
The `+0x20` field is initialized to null in `0066ee90`, copied from the source
object in `00663f50`, lazily populated by `0066eff0`, and released/cleared by
`0066ebc0`. The `AptCIH::GetAnimationInst` reader at `009d1880` returns this
field. Pointer provenance keeps the value reaching the lazy store ambiguous
across five call-result barriers and two null alternatives. See the exact
operation keys in [`field20-memory-store-access.jsonl`](scan37/replay-0041dd40/field20-memory-store-access.jsonl),
[`field20-pcode-flow.tsv`](scan37/replay-0041dd40/field20-pcode-flow.tsv), and
[`field20-pointer-provenance.jsonl`](scan37/replay-0041dd40/field20-pointer-provenance.jsonl).
The new [`TypeLayoutHypothesis/1` row](scan37/replay-0041dd40/field20-type-layout-hypothesis.jsonl)
captures this as an opaque review-level cluster with a 56-byte minimum
observed extent and a 4-byte data-pointer candidate; it leaves exact size and
pointee identity unresolved.
The [`GhidraIndirectCallVtableCandidates/1` first-level capture](scan37/replay-0041dd40/field20-vtable-call-candidates.jsonl)
contains three static target candidates (`00663030`, `00676040`, `006770b0`)
for each first-level call at `006657ed` and `0066582d`, with constructor,
factory, store-graph, vtable-slot, and raw-byte references. The second-level
[`nested candidate capture`](scan37/replay-0041dd40/field20-nested-vtable-call-candidates.jsonl)
records partial target candidates for `00665801` (`00674f10`, `007091d0`) and
`00665841` (`00674f30`, `00677210`) from vtables initialized in returned
subobjects. Those rows retain the parent call, selector case, member offset,
constructor path, and exact P-code store references. A pinned-disassembly
case also traces `00663030` selector 3 to vtable `00af0628`, adding
`007091d0`/`00677210` as another origin pair. The rows remain partial because
runtime selector values, selector-1 returns at `+0x74`, and unobserved writers
remain unresolved. The `/6` results remain unchanged.
The replay also includes the 32-row, read-only generic Ghidra pointer-table
export at [`ghidra-pointer-table-slots.jsonl`](scan37/replay-0041dd40/ghidra-pointer-table-slots.jsonl);
its schema and invocation are documented in
[`Ghidra pointer-table slots`](../../../../GHIDRA_POINTER_TABLE_SLOTS.md).

Scans25–34 exhaust the pinned 2,374-function direct-call-caller population
with at least one explicit `param_n` and a 40–800-byte body. Scan36 covers the
complementary 295 functions in that size range with no outgoing direct-call
row, and scan37 covers all 161 explicit-parameter functions above 800 bytes.
The inventory and call-edge files select targets only; all memory facts
continue to come from the read-only High-P-code exporter. Across scans25–37,
102 exact pairs include three unique structural candidates, 20 possible
pairs, and 79 pairs with non-dominating stores.

Scan26's eight exact same-function pairs occur in four functions. None is a
unique CFG store candidate. Scan27's sixteen pairs occur in ten functions;
again, none is a unique candidate. These are structural candidate results,
not evidence that a runtime value flows between the accesses.

## Bounded `/5` and `/6` replays

The scan26 follow-up in [`replay-004d6700`](scan26/replay-004d6700/) covers two
pairs at offset `0x334`. Its plan has eleven call-argument slots and Ghidra
recovers five exact formal-plus-offset roots. Across the two pairs, the
interprocedural sidecar has six `unknown_effect` and two
`no_aliasing_memory_effect` rows. Both `/5` and `/6` remain
`possible_intervening_memory_effect`; no unique candidate is produced. A
follow-up export reaches `CALLIND` in `0065cd30` below `00637890`, so the
bounded direct-call closure remains incomplete and that unknown effect stays
a barrier. CFG/4 removes duplicate source-linked `INDIRECT` markers without
changing the pair statuses.

The scan27 replay in [`replay-0048e380`](scan27/replay-0048e380/) uses the
dominating store at `0048e3b1` (`param0 + 0x4`) and load at `0048e3f2`. Every
local STORE between them has an exact, disjoint parameter offset. The only
remaining witness barrier is the direct call at `0048e3d5` to `0062e1a0`.
The bounded closure follows
`0048e380 → 0062e1a0 → 00901179 → 0090a62e`, where it reaches a `CALLIND`.
The top call's actual argument is a constant and has no caller-formal root;
one exact root is recovered on the nested `0062e1a0 → 00901179` edge. The
transitive closure is incomplete, so the direct-call effect stays
`unknown_effect`.

On identical pair, P-code, memory-fact, and caller-root inputs, `/5` and `/6`
both retain `possible_intervening_memory_effect` and report zero unique
candidates. CFG/4 reduces the relevant call's unknown-operation identifiers
from 57 to 27 by deduplicating linked markers; the reachable `CALLIND` and
missing nested flows still block filtering. The replay does not promote an
aliasing claim.

## Replay commands

Rebuild the pair graphs and `/6` screen from the retained TSV and JSONL files:

```sh
EVIDENCE=docs/evidence/receiver-field-access/nfs-shift-screening-20261019

revenginstr-receiver-field-access-pairs \
  "$EVIDENCE/scan27/parameter-stores.tsv" \
  "$EVIDENCE/scan27/parameter-loads.tsv" \
  --program-id nfs-shift:SHIFT.exe \
  --output /tmp/scan27-field-access-pairs.jsonl

revenginstr-receiver-field-store-load-dominance-audit \
  "$EVIDENCE/scan27/field-access-pairs.jsonl" \
  "$EVIDENCE/scan27/function-pcode-cfg-v4.jsonl" \
  --memory-store-access-jsonl "$EVIDENCE/scan27/memory-store-access-pair-functions.jsonl" \
  --output /tmp/scan27-dominance-v6.jsonl
```

Use the same commands with `scan26` to replay that sample. To rebuild the
targeted scan27 `/5` and `/6` results, pass the four files under
`replay-0048e380/flows/` as repeated `--pcode-flow ENTRY TSV` arguments to
`revenginstr-interprocedural-memory-effects`; use `function-pcode-cfg-v3-scope.jsonl`
for `/5` and `function-pcode-cfg-v4-scope.jsonl` for `/6`, with the retained
`memory-store-access-scope.jsonl` and `caller-parameter-roots-v2.tsv`. Then
pass the effect JSONL to `revenginstr-receiver-field-store-load-dominance-audit`
with the matching CFG and memory-fact files. The retained files are the exact
outputs of that procedure.

To replay scan29's base screen:

```sh
EVIDENCE=docs/evidence/receiver-field-access/nfs-shift-screening-20261019/scan29

revenginstr-receiver-field-access-pairs \
  "$EVIDENCE/parameter-stores.tsv" \
  "$EVIDENCE/parameter-loads.tsv" \
  --program-id nfs-shift:SHIFT.exe \
  --output /tmp/scan29-field-access-pairs.jsonl

revenginstr-receiver-field-store-load-dominance-audit \
  "$EVIDENCE/field-access-pairs.jsonl" \
  "$EVIDENCE/function-pcode-cfg-v4.jsonl" \
  --memory-store-access-jsonl "$EVIDENCE/memory-store-access-pair-functions.jsonl" \
  --output /tmp/scan29-dominance-v6.jsonl
```

The focused scan29 replay uses the four pairs from
`scan29/replay-00458170/field-access-pairs.jsonl`, the shared CFG/4 and
memory facts from `scan29/`, and the retained caller/callee flows and exact
parameter-root sidecar:

```sh
EVIDENCE=docs/evidence/receiver-field-access/nfs-shift-screening-20261019/scan29
REPLAY="$EVIDENCE/replay-00458170"

revenginstr-interprocedural-memory-effects \
  "$REPLAY/field-access-pairs.jsonl" \
  "$EVIDENCE/function-pcode-cfg-v4.jsonl" \
  "$EVIDENCE/memory-store-access-pair-functions.jsonl" \
  "$REPLAY/caller-parameter-roots-v2.tsv" \
  --pcode-flow 00458170 "$REPLAY/caller-pcode-flow.tsv" \
  --pcode-flow 0067cbc0 "$REPLAY/callee-0067cbc0-pcode-flow.tsv" \
  --output /tmp/scan29-interprocedural-memory-effects-v2.jsonl

revenginstr-receiver-field-store-load-dominance-audit \
  "$REPLAY/field-access-pairs.jsonl" \
  "$EVIDENCE/function-pcode-cfg-v4.jsonl" \
  --memory-store-access-jsonl "$EVIDENCE/memory-store-access-pair-functions.jsonl" \
  --interprocedural-memory-effect-jsonl /tmp/scan29-interprocedural-memory-effects-v2.jsonl \
  --output /tmp/scan29-call-aware-dominance-v6.jsonl
```

These screens and replays make no claim about branch feasibility, function
semantics, or runtime behavior. Missing roots, nested callees, indirect calls,
and unresolved writes remain barriers.

The focused scan37 pointer-slot review and the generic call-result-to-store
replay are documented in
[`scan37/replay-0041dd40/manual-static-vtable-review.md`](scan37/replay-0041dd40/manual-static-vtable-review.md)
and
[`scan37/replay-0041dd40/call-store-flow-replay.md`](scan37/replay-0041dd40/call-store-flow-replay.md).
The latter retains five call-result paths into the reviewed `+0x20` store and
one additional generic call-to-store path; it does not resolve the `MULTIEQUAL`
branch or runtime referent. A wider replay over the 100-function closure P-code
capture emits 32 structural call-to-store graphs in eight functions; paths
through `LOAD` and `MULTIEQUAL` remain address/data dependencies, not runtime
value claims.
