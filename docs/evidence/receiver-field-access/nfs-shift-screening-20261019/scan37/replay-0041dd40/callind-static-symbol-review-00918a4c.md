# Static target identity review: `009189cd:00918a4c`

This review narrows the two call-result barriers in the retained
`PointerProvenance/1` row to named static target candidates. It uses retail
`SHIFT.exe`, SHA-256
`eca479aa2d8dbb88bc55709d91ae5c7159ae1b00fc9555d6701000c26de8aee1`, from the
saved Ghidra project with Java 21, `-readOnly`, and `-noanalysis`.

## Observed paths

`___crtInitCritSecAndSpinCount` loads `DAT_00c328c8` and calls
`FUN_0090aa9e` at `009189e4`. The helper resolves `DecodePointer` from
`KERNEL32.DLL` and applies it to its input. If the decoded pointer is null,
the caller selects a fallback or resolves
`InitializeCriticalSectionAndSpinCount` with `GetProcAddress`. It stores the
selected pointer through `FUN_0090aa27`, which resolves and applies
`EncodePointer`, then calls the unencoded pointer at `00918a4c`.

The two direct stores to `DAT_00c328c8` found by the address-reference export
have distinct roles:

| Store | Source | Meaning |
| --- | --- | --- |
| `009189b7` | `__init_pointers` passes `__encoded_null()` to `FUN_009189b3` | Initialize the encoded cache with a null pointer. |
| `00918a3e` | `___crtInitCritSecAndSpinCount` stores the result of `EncodePointer` | Cache the selected API or fallback pointer for a later decode. |

The fallback address `009189bd` is named
`___crtInitCritSecNoSpinCount@8`. The string capture confirms the resolver
arguments `kernel32.dll` and `InitializeCriticalSectionAndSpinCount`; it also
confirms that the helpers resolve `EncodePointer` and `DecodePointer` from
`KERNEL32.DLL`.

The statically identified candidates at `00918a4c` are therefore:

| Candidate | Static path | Address status |
| --- | --- | --- |
| `KERNEL32.DLL!InitializeCriticalSectionAndSpinCount` | Direct `GetProcAddress` result or the same pointer after encode/decode caching. | Runtime address depends on the loaded OS module. |
| `SHIFT.exe!___crtInitCritSecNoSpinCount@8` | OS/API fallback, also eligible for the encode/decode cache. | `0x009189bd`. |

This does not identify which branch runs or bind the external API's runtime
address. The generic triage and effect closure remain unchanged: the two
P-code call-result alternatives stay `call_barrier` records and the
`CALLIND` stays an effect barrier. The reference export also contains an
analysis `DATA` reference from `__ValidateEH3RN` through `[EDX]`; it is not an
explicit store to the cache, so this review does not claim that direct
references exclude every aliasing or runtime write.

## Pinned evidence

The instruction capture for the caller and four helpers is
[`crt-callind-api-functions.jsonl`](crt-callind-api-functions.jsonl), SHA-256
`61ec3009da1b92af4bd73768121584ecf92eeb61e48038f7776c55cb1f35711a`. The
initializer and cache setter captures are
[`crt-pointer-cache-init-00907737.jsonl`](crt-pointer-cache-init-00907737.jsonl),
SHA-256 `3470667dbd40137c5921926137cb291a4365351bffec48db61b3146cb6e65a5c`,
and
[`crt-pointer-cache-writer-009189b3.jsonl`](crt-pointer-cache-writer-009189b3.jsonl),
SHA-256 `7f2fb5e5c6426fabe0f1b62331adfd95aeac47ba69e94cc79fab46fb82e092cb`.
The focused address-reference export is
[`crt-callind-api-address-references.jsonl`](crt-callind-api-address-references.jsonl),
SHA-256 `8e1e335d05303efb8b9296d5d2359c9905cf5f86cbbb08d1a0a1fd5c19683c07`.
Defined strings from the four retained P-code flows are in
[`crt-callind-api-defined-strings.tsv`](crt-callind-api-defined-strings.tsv),
SHA-256 `df153ea81ba2f0588a61404e194ca0991c0f588c75e83deaaad81d4375e7c37f`.

The call-site and helper P-code flows remain the source for operation-level
lineage: `closure-flows/009189cd.tsv` (SHA-256
`9c9f272c3db53a6612b0e17edfb92fb116fc6c68386b082a36823fc53eb5423f`),
`closure-flows/0090aa9e.tsv` (`f4d2b64e17afd1c576942724d0404ba7809549e53892e732b09d3e049746c53b`),
`closure-flows/0090aa27.tsv` (`fea55aec0fd276ff252281e09c225c52d8ae6caac28d160818cb205a31dcf30a`),
and `closure-flows/009189bd.tsv` (`d8aff1644e7eacfd0c0bfc0098c7025afde6e90fb09396167a7ace79e3d33cc2`).
The triage row is record 17 in `callind-target-triage.jsonl`; its source
`CALLIND` row is record 66 in `closure-flows/009189cd.tsv`.

Reproduce the raw Ghidra captures from the repository root:

```sh
EVIDENCE=docs/evidence/receiver-field-access/nfs-shift-screening-20261019/scan37/replay-0041dd40

GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_function_instructions.sh \
  /home/pes/ghidra_projects/shift shift SHIFT.exe \
  "$EVIDENCE/crt-callind-api-functions.jsonl" \
  0x009189cd 0x0090aa9e 0x0090aa27 0x0090aa95 0x0090a9bb

GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_function_instructions.sh \
  /home/pes/ghidra_projects/shift shift SHIFT.exe \
  "$EVIDENCE/crt-pointer-cache-init-00907737.jsonl" 0x00907737

GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_function_instructions.sh \
  /home/pes/ghidra_projects/shift shift SHIFT.exe \
  "$EVIDENCE/crt-pointer-cache-writer-009189b3.jsonl" 0x009189b3

GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_address_references.sh \
  /home/pes/ghidra_projects/shift shift SHIFT.exe \
  "$EVIDENCE/crt-callind-api-address-references.jsonl" \
  0x00c328c8 0x009189b3 0x009189bd 0x0090aa95 \
  0x00aa61ac 0x00aa61d0 0x00aa62fc \
  0x00b384bc 0x00b384cc 0x00b384dc 0x00b41718 0x00b41740
```

The string capture uses the four P-code flow TSVs cited above as input to
`scripts/run_ghidra_pcode_defined_strings.sh`; it retains only defined strings
referenced by constants in those files. Reproduce that bounded input and
capture with:

```sh
python3 - <<'PY'
from pathlib import Path

root = Path("docs/evidence/receiver-field-access/nfs-shift-screening-20261019/scan37/replay-0041dd40/closure-flows")
sources = ["009189cd.tsv", "0090aa9e.tsv", "0090aa27.tsv", "0090a9bb.tsv"]
Path("/tmp/crt-callind-api-pcode.tsv").write_bytes(
    b"".join((root / name).read_bytes() for name in sources)
)
PY

GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_pcode_defined_strings.sh \
  /home/pes/ghidra_projects/shift shift SHIFT.exe \
  /tmp/crt-callind-api-pcode.tsv \
  "$EVIDENCE/crt-callind-api-defined-strings.tsv"
```
