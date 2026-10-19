# Scoped target observations in the direct-call effect closure /2

This replay uses retail `SHIFT.exe`, SHA-256
`eca479aa2d8dbb88bc55709d91ae5c7159ae1b00fc9555d6701000c26de8aee1`.
The target evidence inputs and hashes are:

- [`GhidraStaticIndirectCallTarget/1`](field20-wrapper-callind-static-targets.jsonl): `81b4464fb2d7c922be1bc2702031d5393ada805f75cd94aa6830ff0dc32dbc03`.
- [`GhidraIndirectCallVtableCandidates/1`](field20-vtable-call-candidates.jsonl): `00aff4b6e0d154c0ccb4e1ab82a31be175dcf283e3487f6fbb8c6c2abf6e09a4`.
- [`GhidraIndirectCallVtableCandidates/1`](field20-nested-vtable-call-candidates.jsonl): `942bdf309ca2b91172536b9da8e948a0d607643ea109c4c709e1d99fdf11bc04`.

The `/2` closure builder joined each evidence record by exact function entry,
CALLIND address, and P-code time, and pinned the source artifact hash and row
index. The singleton wrapper sites `0064a0c0:0064a0ce` and
`0064a100:0064a10e` both carry target `0x00664a10` with scope
`observed_global_singleton_initializer`.

The field-20 sites `006657e0:006657ed` and `00665820:0066582d` each carry the
same three candidates: `0x00663030`, `0x00676040`, and `0x006770b0`, scoped to
observed cached-field constructor variants. The returned-subobject sites
`006657e0:00665801` and `00665820:00665841` carry partial candidate sets
`{0x00674f10, 0x007091d0}` and `{0x00674f30, 0x00677210}` respectively.
Their source records retain the selector, constructor, vtable-slot, raw-byte,
and limitation evidence. These candidate observations do not identify runtime
branch selection or exclude unobserved writers.

All six target-enriched rows keep status `indirect_call`, an empty
`effect_opcodes` list, and no target function in their closure entries. The
static target observations therefore do not remove any call barrier.

## Reproduction

Run from the repository root with the source package on `PYTHONPATH`:

```sh
PYTHONPATH=src python - <<'PY'
from pathlib import Path
from revenginstr.receiver.call_effect_closure import main

base = Path('docs/evidence/receiver-field-access/nfs-shift-screening-20261019/scan37/replay-0041dd40')
flow_dir = base / 'closure-flows'
static = base / 'field20-wrapper-callind-static-targets.jsonl'
vtable = base / 'field20-vtable-call-candidates.jsonl'
nested = base / 'field20-nested-vtable-call-candidates.jsonl'
targets = {
    '0064a0c0': (('static',), ('00648d50', '006657e0')),
    '0064a100': (('static',), ('00648d50', '00665820', '00665880')),
    '006657e0': (('vtable', 'nested'), ()),
    '00665820': (('vtable', 'nested'), ('00665880',)),
}
for caller, (evidence_kinds, callees) in targets.items():
    args = [str(flow_dir / f'{caller}.tsv'), '--program-id', 'nfs-shift:SHIFT.exe']
    if 'static' in evidence_kinds:
        args.extend(['--static-indirect-call-targets', str(static)])
    for evidence in evidence_kinds:
        if evidence == 'vtable':
            args.extend(['--indirect-call-vtable-candidates', str(vtable)])
        elif evidence == 'nested':
            args.extend(['--indirect-call-vtable-candidates', str(nested)])
    args.extend(['--program-sha256', 'eca479aa2d8dbb88bc55709d91ae5c7159ae1b00fc9555d6701000c26de8aee1'])
    for entry in callees:
        args.extend(['--callee-flow', entry, str(flow_dir / f'{entry}.tsv')])
    args.extend(['--output', str(base / f'static-call-target-closure-{caller}.jsonl')])
    main(args)
PY
```

The wrapper results retain their previous direct-call closure statuses:
`0064a0c0` has one `no_explicit_memory_write`, one `unknown_effect`, and one
`indirect_call`; `0064a100` has one `no_explicit_memory_write`, two
`explicit_memory_write`, and one `indirect_call`. `006657e0` has two
`indirect_call` rows. `00665820` has two `indirect_call` rows and one
`explicit_memory_write` row.

## Output hashes

- [`static-call-target-closure-0064a0c0.jsonl`](static-call-target-closure-0064a0c0.jsonl): 3 rows, SHA-256 `e00da7b6e02748bfa7cf8287d9f522365d539dbf6f3995ef4ba5c1f93550fd0a`.
- [`static-call-target-closure-0064a100.jsonl`](static-call-target-closure-0064a100.jsonl): 4 rows, SHA-256 `62e828d27718feb2bb7cc2a403b5effc9bb5e303426fab10936c2620115729ff`.
- [`static-call-target-closure-006657e0.jsonl`](static-call-target-closure-006657e0.jsonl): 2 rows, SHA-256 `385d50555136928f899d5e54e1c211e35cfa287302edd25953f779d108965553`.
- [`static-call-target-closure-00665820.jsonl`](static-call-target-closure-00665820.jsonl): 3 rows, SHA-256 `a488b045cc14eb9b17b53a20493b70314d10f07c76bc4d6b0ce0a5dc688eea48`.

Each artifact adds scoped target observations while preserving the existing
effect statuses and the runtime limitations recorded in the source evidence.
