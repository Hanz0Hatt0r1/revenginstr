# Analysis Feedback

`REVENGINSTR.AnalysisFeedback/1` is a consumer-owned JSONL contract for
reviewing a function, family, claim, or routing decision. The bounded outcomes
are `confirmed`, `rejected`, `partially_correct`, `ambiguous`, and
`needs_more_evidence`.

Each row pins its target artifact and record, records an opaque reviewer id,
reviewer kind and qualification, declares reviewer-assessed provenance quality,
and cites one or more evidence records with their evidence classes. Reviewer
and subject identities, labels, and evidence rows remain in the consumer
repository; this generic schema contains no project-specific examples or free
text field.

Automated reviewers use the `automated` qualification; human reviewers use an
expert, trained, peer, or unknown qualification. Evidence references are unique
within each feedback row.

`training_eligible` is fixed to `false`: raw feedback is an audit signal, not
adjudicated training truth. A consumer must separately curate and adjudicate
labels before using them in a training dataset.
