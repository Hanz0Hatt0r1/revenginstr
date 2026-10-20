# NFS SHIFT state-machine candidate scan

This scan replays `StateMachineCandidateAudit/2` over fourteen function-scoped
captures from the NFS SHIFT M2.3 evidence in
[consumer PR #2099](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/pull/2099),
at commit
[`f165ca7e9c9bfb0e4b1dcfb1a05543ec42d7bd40`](https://github.com/Hanz0Hatt0r1/nfs-shift-decompilation/commit/f165ca7e9c9bfb0e4b1dcfb1a05543ec42d7bd40).
The new `--function-entry` selector lets the analyzer use a CFG for one
function with a P-code capture that also contains neighboring functions. It
keeps hashes for the original input files and preserves their original row
indices.
The selected entry is explicit in every report, including no-candidate rows;
see the
[`/2` schema](../../../schemas/state-machine-candidate-audit-v2.schema.json).

## Results

The detector found two structural candidates in fourteen function slices.
Both positive joins were checked against the original P-code, parameter-load,
memory-store, and CFG rows. Twelve slices did not match this bounded pattern;
that does not imply they lack state behavior.

| Function | P-code ops | Loads | Stores | Candidates | Retained audit SHA-256 |
| --- | ---: | ---: | ---: | ---: | --- |
| `00503790` | 43 | 2 | 7 | 0 | `e3937f6419017a64607352b1dec8d277942c69dceeb1206ea23493f65cdf8895` |
| `0060de20` | 45 | 2 | 3 | 0 | `79732f4b10f4d2f2b6750d1f6b7faf3c1876ba4cfd5bf2fe8813978eebcd4115` |
| `00619b7d` | 77 | 6 | 7 | 0 | `5b331e625288c7a488d9244e8cb90e0072921a4972428cb8dbe616e6739ca291` |
| `00620a38` | 246 | 7 | 4 | 1 | `b7deaecaab20ba88d42c8f708a38c56d2b123fd61c37bbce53ab42d7c9c60942` |
| `00880bf0` | 142 | 16 | 8 | 0 | `d6a14bb830ea54744d6e69480c7c1c1c243ce3f9e64240df6fb1003c1b21f79b` |
| `00891be0` | 200 | 12 | 7 | 0 | `3e51b670273475f8d210932e0a33e923d4147bf1a676c80a012e5f82aacfbe32` |
| `009cf690` | 237 | 17 | 6 | 0 | `c2d2f048f4d66c19b6ff40fe87c5f31e750412503aa3e1a3ed11cec59bfa0bae` |
| `00a0a740` | 113 | 6 | 5 | 0 | `c0b345c46581fc7a8ee18a7c7d61f6b2564320e0a067505f47bd1a1196650843` |
| `00a3d3c0` | 500 | 3 | 67 | 0 | `b14bb3f2fe16a6915113953a291a3ad991f56ae3ebcaed30cd83f54c68244ee0` |
| `00a3d7d0` | 331 | 2 | 43 | 0 | `34900ccc57956308fa0ae5155109de0efe0bdc09481989f7730b5f85b1eadf05` |
| `00a3dda0` | 379 | 3 | 50 | 0 | `385b4dc938a6877dcc521745566444bdb14ade51990a36d728dd5091b2955eae` |
| `00a45520` | 40 | 2 | 8 | 0 | `ea579ee5b45af983f14e318a3f49f1dd45a53f5a90a3605664294b427b7eb0ae` |
| `00a45b50` | 68 | 6 | 8 | 1 | `53cf3460e6cacb1d5777d907512ebf52682461b0d60168dfea7803608016f74f` |
| `00a277d0` | 169 | 12 | 3 | 0 | `72f63df638550a9a2b358ba3669336926e6d1b2bfa2ff831bd828029a24fa0e6` |

The first candidate reads parameter 0 at offset `0x14`, compares the value,
branches, and writes the same parameter field from CFG successor block 1. Its
source P-code rows are 48, 49, 51, and 67. The second reads parameter 3 at
offset `0x0` and writes the same field from successor block 4; its source rows
are 20, 21, 22, and 26. Each write block is reachable from exactly one of the
two branch successors in the captured CFG. The indices in the report point to
the original, unfiltered artifacts.

These are structural candidates only. The scan does not infer branch
polarity, runtime values, path feasibility, or semantic state transitions.
The state-machine replay remains separate from the semantic graph; it does
not establish accepted-edge precision or close M5.4/M10.

## Replay

Set `NFS_M23` to the
`evidence/revenginstr_m23_direct_call_replay` directory from the pinned NFS
commit. Rebuild either positive result with:

```sh
revenginstr-state-machine-candidates \
  "$NFS_M23/00620a38/function-pcode-cfg-v3.jsonl" \
  "$NFS_M23/00620a38/bounded-pcode.tsv" \
  "$NFS_M23/00620a38/parameter-loads.tsv" \
  "$NFS_M23/00620a38/memory-store-access.jsonl" \
  --function-entry 00620a38 \
  --output /tmp/00620a38-state-candidates.json
```

For the `00a45b50` slice, substitute `00a45b50` for the directory and selected
function entry in that command. The retained JSON audits in this directory
record every slice's selected entry, full source hashes, scoped row counts,
candidate ids, and source record indices.

To rebuild the full fourteen-function scan, run the same command for each
entry below, writing to a temporary directory, then run the separate scan22
command. The scan22 P-code input is in `caller-pcode-flow`:

```sh
OUT=/tmp/nfs-shift-m23-state-candidates
mkdir -p "$OUT"
for entry in 00503790 0060de20 00619b7d 00620a38 00880bf0 00891be0 \
             009cf690 00a0a740 00a3d3c0 00a3d7d0 00a3dda0 00a45520 00a45b50; do
  revenginstr-state-machine-candidates \
    "$NFS_M23/$entry/function-pcode-cfg-v3.jsonl" \
    "$NFS_M23/$entry/bounded-pcode.tsv" \
    "$NFS_M23/$entry/parameter-loads.tsv" \
    "$NFS_M23/$entry/memory-store-access.jsonl" \
    --function-entry "$entry" --output "$OUT/$entry.json"
done
revenginstr-state-machine-candidates \
  "$NFS_M23/screening-scan22/function-pcode-cfg-v3.jsonl" \
  "$NFS_M23/screening-scan22/caller-pcode-flow/00a277d0.tsv" \
  "$NFS_M23/screening-scan22/parameter-loads.tsv" \
  "$NFS_M23/screening-scan22/memory-store-access.jsonl" \
  --function-entry 00a277d0 --output "$OUT/scan22-00a277d0.json"
```

Compare each generated JSON object with the matching retained audit; the
reports pin the original artifacts and retain original row numbering.
