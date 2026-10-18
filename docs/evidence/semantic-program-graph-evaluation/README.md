# Semantic Program Graph evaluation replays

These small review-curated gold rows cross-check exact `calls` edges against
the captured Ghidra Function P-code rows. They exercise the evaluator on real
NFS SHIFT and GT5 Prologue exports. They are projection audits, not complete
consumer subsystem gold sets or independent semantic-understanding
evaluations; those remain consumer-owned roadmap work.

| Capture | Gold calls | Matched | Unsupported rate | Provenance fields | Accepted edges |
| --- | ---: | ---: | ---: | ---: | ---: |
| [GT5 Prologue function `00032830`](gt5-prologue-00032830/README.md) | 2 | 2 | 0% | 100% | 0 |
| [NFS SHIFT call-path slice](nfs-shift-call-path/README.md) | 7 | 7 | 0% | 100% | 0 |

All nine matched edges carry a source format, artifact hash and record index.
Both captures have null graph-edge confidence, so accepted-edge precision is
`null`; neither replay passes the accepted-edge precision gate. The evaluator
does not count relations outside the explicitly complete `calls` scope as
negative labels.
