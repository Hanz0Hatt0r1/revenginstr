# CALLIND target-provenance triage

This replay summarizes each exact `callind_target` row in
[`closure-pointer-provenance.jsonl`](closure-pointer-provenance.jsonl), whose
SHA-256 is `8a026a517f7bd9be9200e158a712fa0559fa8c665e60a3900347063a69371f5b`.
The output is
[`callind-target-triage.jsonl`](callind-target-triage.jsonl), SHA-256
`582d0793e3fae55fc84fc56f5caf6fefc120d35ec12eae8d4a7138fbb5741cb9` (22
rows).

Reproduce from the repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m revenginstr.indirect_call_target_triage \
  --program-id nfs-shift:SHIFT.exe \
  --program-sha256 eca479aa2d8dbb88bc55709d91ae5c7159ae1b00fc9555d6701000c26de8aee1 \
  --pointer-provenance docs/evidence/receiver-field-access/nfs-shift-screening-20261019/scan37/replay-0041dd40/closure-pointer-provenance.jsonl \
  --output /tmp/callind-target-triage.jsonl
```

The 22 sites classify as six `bounded_provenance_only`, thirteen
`dynamic_barrier_only`, and three `mixed_bounded_and_blocked`. The six bounded
rows are the previously reviewed singleton/vtable paths; provenance alone
does not establish complete target sets. The sixteen sites beyond those six
have no complete target set. One mixed site now contributes a partial static
candidate after correcting `PTRSUB` to add its byte offset to the base pointer:

| Function | CALLIND address | Bounded paths | Dynamic barriers | Partial candidate |
| --- | --- | ---: | ---: | --- |
| `0090aa27` | `0090aa89` | 1 | 1 | — |
| `0090aa9e` | `0090ab00` | 1 | 1 | — |
| `009189cd` | `00918a4c` | 1 | 2 | `0x009189bd` |

At `00918a4c`, alternative 1 is rooted at `const:0x0:4` with offset
`+0x9189bd`, matching retained function entry `009189bd`. The two other
alternatives remain call barriers at `009189e4` and `00918a26`; the candidate
is therefore partial. The focused `/2` closure preserves status
`indirect_call`, adds one target observation with evidence state
`partial_static_target_candidates`, and does not include the candidate flow
in its direct-call closure. See the
[closure replay](static-call-target-closure-replay.md).

All 22 sites remain `CALLIND` effect barriers. Runtime acquisition or stronger
validated call-result summaries are still needed to cover the dynamic paths.
For `009189cd:00918a4c`, a manual, source-pinned review now narrows both
call-result barriers to the symbolic candidate set
`KERNEL32.DLL!InitializeCriticalSectionAndSpinCount` and
`SHIFT.exe!___crtInitCritSecNoSpinCount@8` (`0x009189bd`). The external API's
runtime address and branch selection remain unresolved, and the indirect
cache has a possible aliasing reference; this evidence does not change the
generic triage JSONL or remove the effect barrier. See
[`callind-static-symbol-review-00918a4c.md`](callind-static-symbol-review-00918a4c.md).
