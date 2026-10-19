# Semantic Program Graph evaluation replays

These replays exercise the evaluator on real Ghidra Function P-code exports.
GT5 Prologue and NFS SHIFT are projection audits. The Nevergone row is the
first narrow consumer-owned gold subgraph, manually adjudicated against its
project recovery note and source P-code rows.

| Capture | Gold calls | Matched | Unsupported rate | Provenance fields | Accepted edges |
| --- | ---: | ---: | ---: | ---: | ---: |
| [GT5 Prologue function `00032830`](gt5-prologue-00032830/README.md) | 2 | 2 | 0% | 100% | 0 |
| [NFS SHIFT call-path slice](nfs-shift-call-path/README.md) | 7 | 7 | 0% | 100% | 0 |
| [Nevergone player-facing calls](nevergone-player-horizontal-facing/README.md) | 3 | 3 | 0% | 100% | 0 |

All twelve matched edges carry source format, artifact hash and record index.
All three graph captures have null edge confidence, so accepted-edge precision
is `null`; none passes the accepted-edge precision gate. The Nevergone note
and P-code export describe the same shipped binary, so its gold is an
independently curated consumer interpretation, not independent binary or
runtime corroboration. The evaluator does not count relations outside each
explicitly complete `calls` scope as negative labels.
