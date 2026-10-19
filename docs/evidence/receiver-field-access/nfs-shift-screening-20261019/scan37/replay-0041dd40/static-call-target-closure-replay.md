# Scoped target observations in the direct-call effect closure /2

This replay uses retail `SHIFT.exe`, SHA-256
`eca479aa2d8dbb88bc55709d91ae5c7159ae1b00fc9555d6701000c26de8aee1`.
The target evidence inputs and hashes are:

- [`GhidraStaticIndirectCallTarget/1`](field20-wrapper-callind-static-targets.jsonl): `dcf77714b6a9c9d76c80ea5435c0592a738a66908464605bdfc4886d68606231`.
- [`GhidraIndirectCallVtableCandidates/1`](field20-vtable-call-candidates.jsonl): `7fe629f1086028b447b97f57eee865b97422fecddcf29df4bfc5f33fdc983703`.
- [`GhidraIndirectCallVtableCandidates/1`](field20-nested-vtable-call-candidates.jsonl): `95fd25b48536e82ac2e5be2639f58e61befab03d65969d84a1fc320a1d9ecfae`.
- [`IndirectCallTargetTriage/1`](callind-target-triage.jsonl): `582d0793e3fae55fc84fc56f5caf6fefc120d35ec12eae8d4a7138fbb5741cb9`.

The `/2` closure builder joins each evidence record by exact function entry,
CALLIND address, and P-code time, and pins the source artifact hash and row
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

Correct `PTRSUB` handling also exposes one constant-address path at
`009189cd:00918a4c`: candidate `0x009189bd`, derived from `const:0x0:4` plus
`0x9189bd`. Its two other target alternatives are call barriers, so the
observation is `partial_static_target_candidates`. The focused output
[`static-call-target-closure-009189cd.jsonl`](static-call-target-closure-009189cd.jsonl)
joins this triage row by exact call identity. It has seven caller call-site
rows (one `indirect_call`, four `missing_callee_flow`, and two
`unresolved_target`); the candidate row retains status `indirect_call`, an
empty `effect_opcodes` list, and no candidate in `closure_function_entries`.
The target address is recorded as an observation only and is not treated as a
closed direct call.

All seven target-enriched sites keep status `indirect_call`, an empty
`effect_opcodes` list, and no candidate target function in their closure
entries. The observations therefore do not remove any call barrier.

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
triage = base / 'callind-target-triage.jsonl'
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

main([
    str(flow_dir / '009189cd.tsv'), '--program-id', 'nfs-shift:SHIFT.exe',
    '--indirect-call-target-triage', str(triage),
    '--program-sha256', 'eca479aa2d8dbb88bc55709d91ae5c7159ae1b00fc9555d6701000c26de8aee1',
    '--output', str(base / 'static-call-target-closure-009189cd.jsonl'),
])
PY
```

The original wrapper results retain their direct-call closure statuses:
`0064a0c0` has one `no_explicit_memory_write`, one `unknown_effect`, and one
`indirect_call`; `0064a100` has one `no_explicit_memory_write`, two
`explicit_memory_write`, and one `indirect_call`. `006657e0` has two
`indirect_call` rows. `00665820` has two `indirect_call` rows and one
`explicit_memory_write` row.

## Output hashes

- [`static-call-target-closure-0064a0c0.jsonl`](static-call-target-closure-0064a0c0.jsonl): 3 rows, SHA-256 `9f60dc92ae2380ff754d616531ef3618bda67c4507436dc4b4759413b7832a31`.
- [`static-call-target-closure-0064a100.jsonl`](static-call-target-closure-0064a100.jsonl): 4 rows, SHA-256 `f6daf40d8dcbd80d0ce96fe10daf0381892c0731575ad3d29cc1753b87bf41aa`.
- [`static-call-target-closure-006657e0.jsonl`](static-call-target-closure-006657e0.jsonl): 2 rows, SHA-256 `5a3a575627328bd33061e886e2153976c3503cb65287bf43f93e852d2da6f08a`.
- [`static-call-target-closure-00665820.jsonl`](static-call-target-closure-00665820.jsonl): 3 rows, SHA-256 `0ecc1ce1babf3759da1a86287ac580eb291bf0c0c91d566941f17a8deb96be59`.
- [`static-call-target-closure-009189cd.jsonl`](static-call-target-closure-009189cd.jsonl): 7 rows, SHA-256 `86e3c52d78ab1703f02502aeabcb83d33f95b54a33e7e64158362b6bd3debb46`.

Each artifact adds scoped target observations while preserving the existing
effect statuses and the runtime limitations recorded in the source evidence.
