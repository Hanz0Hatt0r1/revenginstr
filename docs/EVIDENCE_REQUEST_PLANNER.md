# Bounded evidence request planner

`EvidenceRequestCandidates/1` is a caller-owned list of reviewed actions for
unresolved subjects. Every request uses one supported action type, finite
limits, an opaque review-record hash, a cost estimate, and caller estimates
for uncertainty reduction and downstream leverage.

```json
{
  "format": "REVENGINSTR.EvidenceRequestCandidates/1",
  "candidates": [
    {
      "request_id": "slice-subject-1",
      "subject_id": "subject-1",
      "subject_kind": "function",
      "action_type": "function_slice",
      "bounds": {"max_items": 250},
      "cost_units": 2,
      "expected_uncertainty_reduction": 0.6,
      "downstream_leverage": 3.0,
      "rationale_codes": ["missing_receiver_provenance"],
      "approval_status": "approved",
      "approval_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
  ]
}
```

Supported actions are `function_slice`, `callers_callees`,
`field_store_recovery`, `constructor_vtable_anchor`,
`consumer_native_probe`, `family_example`, and `human_review`. Each action has
required explicit bounds. Native probes require both `max_steps` and
`timeout_ms`; an optional `probe_kind` identifies function entry/exit,
field-watch read/write, argument/return sampling, call/dispatch tracing,
allocation/lifetime, state snapshots, or a consumer-defined differential
intervention. Older generic native-probe requests remain valid. Probe requests
cannot carry executable code or arbitrary command arguments. Human review is
limited to one item per request.

Create a plan with a fixed integer cost budget and maximum request count:

```sh
revenginstr-evidence-request-plan candidates.json \
  --budget-units 20 \
  --max-requests 10 \
  --output evidence-request-plan.json
```

The planner ranks candidates by
`downstream_leverage * expected_uncertainty_reduction / cost_units`, selects at
most one request per subject, and skips requests that exceed the remaining
budget or count. The report pins the candidate file hash and gives aggregate
deferred counts. Equal scores break ties by request ID.

Approval, cost, leverage, and expected reduction are caller-supplied
declarations, not independently verified facts. The tool only validates and
prioritizes them: it never executes an action, constructs a probe, or promotes
a model result to evidence. Use the artifact review process of the consumer
repository to approve a candidate before planning it.
