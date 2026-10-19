# Static target observations in the direct-call effect closure /2

This replay uses the retail `SHIFT.exe` binary pinned by SHA-256
`eca479aa2d8dbb88bc55709d91ae5c7159ae1b00fc9555d6701000c26de8aee1` and the
reviewed [`GhidraStaticIndirectCallTarget/1` records](field20-wrapper-callind-static-targets.jsonl).
The target-evidence file SHA-256 is
`81b4464fb2d7c922be1bc2702031d5393ada805f75cd94aa6830ff0dc32dbc03`.

The `/2` closure builder joined only exact function entry, CALLIND address, and
P-code time. It pinned each matched target record by artifact hash and row
index. The records for `0064a0c0:0064a0ce` and `0064a100:0064a10e` both report
target `0x00664a10`. Both output rows keep status `indirect_call`, an empty
`effect_opcodes` list, and no target function in their closure entries. This
is a scoped static observation for the singleton initializer path; it does not
rule out a runtime mutation of the global pointer.

## Reproduction

Run from the repository root with the source package on `PYTHONPATH`:

```sh
PYTHONPATH=src python - <<'PY'
from pathlib import Path
from revenginstr.receiver.call_effect_closure import main

base = Path('docs/evidence/receiver-field-access/nfs-shift-screening-20261019/scan37/replay-0041dd40')
flow_dir = base / 'closure-flows'
targets = {
    '0064a0c0': ('00648d50', '006657e0'),
    '0064a100': ('00648d50', '00665820', '00665880'),
}
for caller, callees in targets.items():
    args = [
        str(flow_dir / f'{caller}.tsv'),
        '--program-id', 'nfs-shift:SHIFT.exe',
        '--static-indirect-call-targets', str(base / 'field20-wrapper-callind-static-targets.jsonl'),
        '--program-sha256', 'eca479aa2d8dbb88bc55709d91ae5c7159ae1b00fc9555d6701000c26de8aee1',
    ]
    for entry in callees:
        args.extend(['--callee-flow', entry, str(flow_dir / f'{entry}.tsv')])
    args.extend(['--output', str(base / f'static-call-target-closure-{caller}.jsonl')])
    main(args)
PY
```

All direct callees reachable from these wrappers have retained flows. The
result for `0064a0c0` has three call rows: one `no_explicit_memory_write`, one
`unknown_effect`, and the target-enriched `indirect_call`. The result for
`0064a100` has four call rows: one `no_explicit_memory_write`, two
`explicit_memory_write`, and the target-enriched `indirect_call`.

## Output hashes

- [`static-call-target-closure-0064a0c0.jsonl`](static-call-target-closure-0064a0c0.jsonl): 3 rows, SHA-256 `0d538c26b4d34c41405477071b42b83d2554cd76799ee7e67202b9650ea71f11`.
- [`static-call-target-closure-0064a100.jsonl`](static-call-target-closure-0064a100.jsonl): 4 rows, SHA-256 `185cff0569db49dfd1f392adc32336225680bd8f88b67dd970965f7fa28cf2a8`.

The outputs add target provenance for these two sites while preserving all
effect statuses. The existing audits therefore continue to treat each
indirect call as a barrier until runtime state or broader static evidence can
justify a stronger claim.
