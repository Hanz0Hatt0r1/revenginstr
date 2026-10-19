# Semantic Program Graph evaluation replays

These replays exercise the evaluator on real Ghidra Function P-code exports.
GT5 Prologue and the NFS SHIFT call-path slice are projection audits.
Nevergone and NFS M2.3 add two narrow consumer-owned gold subgraphs; the NFS
slice labels structural calls and parameter-rooted field accesses only.

| Replay | Gold edges | Matched | Unsupported rate | Provenance fields | Accepted edges |
| --- | ---: | ---: | ---: | ---: | ---: |
| [GT5 Prologue function `00032830`](gt5-prologue-00032830/README.md) | 2 | 2 | 0% | 100% | 0 |
| [NFS SHIFT call-path slice](nfs-shift-call-path/README.md) | 7 | 7 | 0% | 100% | 0 |
| [Nevergone player-facing calls](nevergone-player-horizontal-facing/README.md) | 3 | 3 | 0% | 100% | 0 |
| [Nevergone runtime resource-loader calls](nevergone-runtime-resource-loader-20261020/README.md) | 36 | 36 | 0% | 100% | 0 |
| [NFS M2.3 structural slice](nfs-m23-00a45520/README.md) | 10 | 10 | 0% | 100% | 0 |

All fifty-eight matched edges carry source format, artifact hash and record
index. All five graph captures have null edge confidence, so accepted-edge
precision is `null`; none passes the accepted-edge precision gate. The
consumer-owned golds are manually adjudicated structural interpretations.
The runtime resource-loader replay independently cross-checks exact static
call references; its runtime capture corroborates only function entry, not
those call edges. The NFS field slice does not assign field meaning or prove
store-to-load flow. The evaluator does not count relations outside each
explicitly complete relation scope as negatives.
