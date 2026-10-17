# Receiver candidate assessment

`ReceiverCandidateAssessment/1` is an optional sidecar produced by
`revenginstr-receiver-infer --candidate-assessments-output`. The existing
`ReceiverInference/1` records and status meanings remain unchanged.

The assessment distinguishes:

- `same_type_convergence`: one known candidate class and no unresolved typed source;
- `compatible_subtype_candidates`: multiple candidates with one consumer-declared compatibility group and no unresolved typed source;
- `mixed_candidates`: known candidates span compatibility groups or lack a shared declared group;
- `partially_unknown_candidates`: known candidates are mutually compatible, but at least one typed source did not resolve;
- `no_known_candidates`: no candidate class can be named from the current evidence.

Consumers may add `receiver_compatibility_group_id` to catalog rows. The group
is an explicit consumer-owned claim that the grouped classes are compatible
subtype candidates; the tool does not verify inheritance. A class that appears
with conflicting group ids is treated as ungrouped. Without the field, multiple
class candidates remain mixed. Ambiguous terminal type
names retain all matching catalog classes in the assessment sidecar, while the
legacy inference result continues to abstain as before.

The sidecar follows input call order and joins on `source_id` plus `call_index`.
Class names and compatibility ids are copied from the consumer catalog; this
shared repository defines only their wire shape and decision rules. The
assessment does not select a receiver, authorize target transfer, or affect
routing.

```sh
revenginstr-receiver-infer receiver-types.tsv catalog.jsonl \
  --output receiver-inference.jsonl \
  --candidate-assessments-output candidate-assessments.jsonl
```
