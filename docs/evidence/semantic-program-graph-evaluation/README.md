# Semantic Program Graph evaluation replays

These replays exercise the evaluator on real Ghidra Function P-code exports.
GT5 Prologue and the NFS SHIFT call-path slice are projection audits.
Nevergone and NFS M2.3 add two narrow consumer-owned gold subgraphs; the NFS
slice labels structural calls and parameter-rooted field accesses only.

| Replay | Gold edges | Matched | Unsupported rate | Provenance fields | Accepted edges | Accepted precision |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| [GT5 Prologue function `00032830`](gt5-prologue-00032830/README.md) | 2 | 2 | 0% | 100% | 2 | 1.0 |
| [NFS SHIFT call-path slice](nfs-shift-call-path/README.md) | 7 | 7 | 0% | 100% | 7 | 1.0 |
| [Nevergone player-facing calls](nevergone-player-horizontal-facing/README.md) | 3 | 3 | 0% | 100% | 3 | 1.0 |
| [Nevergone runtime resource-loader calls](nevergone-runtime-resource-loader-20261020/README.md) | 36 | 36 | 0% | 100% | 36 | 1.0 |
| [NFS M2.3 structural slice](nfs-m23-00a45520/README.md) | 10 | 10 | 0% | 100% | 7 | 1.0 |

All fifty-eight matched edges carry source format, artifact hash and record
index. Across the five scopes, 55 exact-static direct calls are accepted and
all 55 match the reviewed labels (precision 1.0). The remaining three NFS
field-access edges stay review-only because their evidence is derived
structural and has no calibrated confidence. Graph confidence values remain
null throughout; exact evidence is not converted into a probability. The
consumer-owned golds are manually adjudicated structural interpretations.
The runtime resource-loader replay independently cross-checks exact static
call references; its runtime capture corroborates only function entry, not
those call edges. The NFS field slice does not assign field meaning or prove
store-to-load flow. The evaluator does not count relations outside each
explicitly complete relation scope as negatives.
