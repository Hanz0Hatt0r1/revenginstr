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

## Symbolic target enrichment

`callind-symbol-candidates.jsonl` supplies evidence-backed identities for the
three initially reviewed sites: `KERNEL32.DLL!InitializeCriticalSectionAndSpinCount`
and `SHIFT.exe!___crtInitCritSecNoSpinCount@8` at `009189cd:00918a4c`, plus
partial `KERNEL32.DLL!EncodePointer` and `KERNEL32.DLL!DecodePointer` paths at
`0090aa89` and `0090ab00`. The helper candidates cover only alternative 2;
unresolved cache loads remain visible.

The second static pass adds seven exact dynamic-call identities:

| Function | CALLIND | Symbolic target | Alternative |
| --- | --- | --- | ---: |
| `00907467` | `00907485` | `SHIFT.exe!__exit` (`0x00907708`) | 1 |
| `0090748b` | `009074ae` | `mscoree.dll!CorExitProcess` | 1 |
| `0091c073` | `0091c17c` | `USER32.DLL!GetProcessWindowStation` | 1 |
| `0091c073` | `0091c18f` | `USER32.DLL!GetUserObjectInformationA` | 1 |
| `0091c073` | `0091c1e3` | `USER32.DLL!GetActiveWindow` | 1 |
| `0091c073` | `0091c204` | `USER32.DLL!GetLastActivePopup` | 1 |
| `0091c073` | `0091c225` | `USER32.DLL!MessageBoxA` | 1 |

At `0090748b`, the instructions call the imported `GetModuleHandleA` with the
retained `mscoree.dll` string, call imported `GetProcAddress` with
`CorExitProcess`, check for null, then call the returned pointer. In
`0091c073`, the code loads `USER32.DLL`, resolves the five API names through
`GetProcAddress`, encodes each returned pointer into one of five globals, then
decodes those globals immediately before the matching `CALLIND`. The Ghidra
address-reference export shows only the expected initialization/read uses for
those five globals in this program image. Static aliases and runtime writes
cannot be excluded, and no runtime target was observed.

The same pass resolves `__amsg_exit`'s cached target conditionally: the global
`PTR___exit` has one writer in `__init_pointers`, which passes address
`0x00907708` to `EncodePointer` and stores the result; `__amsg_exit` later
loads, decodes, and calls it. Ghidra identifies `0x00907708` as internal
function `__exit`. The candidate depends on the initializer having run, which
is not established by this static capture.

The sidecar pins each identity to instruction, defined-string, address-metadata,
P-code-flow, CALLIND, and (for encoded globals) address-reference rows. The
retained captures are `callind-blocker-functions.jsonl` (8 functions),
`callind-blocker-defined-strings.tsv` (11 strings),
`callind-blocker-api-address-metadata.jsonl` (3 addresses), and
`callind-blocker-cache-address-references.jsonl` (5 globals). The `__exit`
review adds a target-function listing, the initializer's cache write, and a
reader/writer xref for `PTR___exit`. The API candidates do not establish
runtime execution, external API addresses, or complete target sets; `__exit`
remains conditional on initializer execution.

The `/2` replay is
[`callind-target-triage-v2.jsonl`](callind-target-triage-v2.jsonl), SHA-256
`97f6faf007ddd898179babfea6a85cd30f439bf9541a863a30d0dbd798ddd028` (22
rows; ten annotated sites and eleven symbolic candidates). Its input sidecar is
[`callind-symbol-candidates.jsonl`](callind-symbol-candidates.jsonl), SHA-256
`aa1c6fad685e117f001f2a860322417d54d4d75799e92b29d7747adc34b24c25` (10
rows). Reproduce it from the repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=src python -m revenginstr.indirect_call_target_triage_v2 \
  --target-triage docs/evidence/receiver-field-access/nfs-shift-screening-20261019/scan37/replay-0041dd40/callind-target-triage.jsonl \
  --symbolic-candidates docs/evidence/receiver-field-access/nfs-shift-screening-20261019/scan37/replay-0041dd40/callind-symbol-candidates.jsonl \
  --output /tmp/callind-target-triage-v2.jsonl
```

All `/1` provenance and counts are preserved. The `/2` rows add symbolic
candidate annotations without asserting path feasibility, runtime selection,
or an external address; every site remains a `CALLIND` effect barrier.
