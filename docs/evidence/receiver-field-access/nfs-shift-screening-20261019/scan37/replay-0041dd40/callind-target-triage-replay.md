# CALLIND target-provenance triage

This replay summarizes each exact `callind_target` row in
[`closure-pointer-provenance.jsonl`](closure-pointer-provenance.jsonl), whose
SHA-256 is `05c954fde3df954d037aa832fe8f0b423822e70267b12be9f0ea0429526f5f7c`.
The output is
[`callind-target-triage.jsonl`](callind-target-triage.jsonl), SHA-256
`2086f6d4828bfb3f03f4dcb115f4774df488c081dd556fe68a686edfed860580` (22
rows).

Reproduce from the repository root:

```sh
PYTHONPATH=src python -m revenginstr.indirect_call_target_triage \
  --program-id nfs-shift:SHIFT.exe \
  --pointer-provenance docs/evidence/receiver-field-access/nfs-shift-screening-20261019/scan37/replay-0041dd40/closure-pointer-provenance.jsonl \
  --output /tmp/callind-target-triage.jsonl
```

The 22 sites classify as six `bounded_provenance_only`, thirteen
`dynamic_barrier_only`, and three `mixed_bounded_and_blocked`. The six with
bounded provenance are the previously reviewed singleton/vtable paths; the
triage itself does not establish complete target sets. The other sixteen
remain without target observations. Thirteen have only call/dispatch barriers;
three retain both a bounded provenance path and a dynamic barrier:

| Function | CALLIND address | Bounded paths | Dynamic barriers |
| --- | --- | ---: | ---: |
| `0090aa27` | `0090aa89` | 1 | 1 |
| `0090aa9e` | `0090ab00` | 1 | 1 |
| `009189cd` | `00918a4c` | 1 | 2 |

The mixed rows are partial acquisition leads: their bounded alternatives do
not cover the dynamic alternatives. All sites remain `CALLIND` effect
barriers. Resolving these families requires consumer-collected runtime target
observations or stronger, separately validated summaries for the call results.
