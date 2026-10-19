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
to `SHIFT.exe`; the executable hash is unchanged. Ghidra ran read-only with
analysis disabled for all evidence exports.

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
