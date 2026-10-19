# Repeated runtime intervention evidence

`revenginstr-runtime-intervention` aggregates at least three distinct
`RuntimeDifferential/1` reports. Its manifest pins every report by relative
path and SHA-256 and declares the one intervention, fixed-context hash, and
observation-window hash that all comparisons must share.

The aggregator rejects repeated comparison IDs, capture IDs, or underlying
correlation-report hashes. These unique identifiers make accidental reuse
visible; the tool cannot independently establish that captures were performed
as separate trials. Every pair must describe the same program, graph,
static identity, intervention, and baseline/treatment labels.

A changed signature is labeled `intervention_support` only when all of these
conditions hold:

- there are at least three distinct pairs;
- every baseline and treatment capture is marked `complete` with no sample gaps;
- the signature changes in the same nonzero direction in every pair.

Other signatures remain `correlation`. The report includes signed deltas for
pairs where the signature changed; a missing pair in that list means a zero
delta. The median includes those zero-delta pairs. This version compares event
frequencies, not event order, runtime values, or equal observation duration.
The fixed-context and observation-window hashes are caller-declared, so they
do not prove that the environment or capture duration was held constant.
`intervention_support` is repeatable correlation evidence;
`confirmed_exact` value-flow evidence remains a separate, unimplemented step.

Create a manifest whose paths are relative to the manifest directory:

```json
{
  "format": "REVENGINSTR.RuntimeInterventionManifest/1",
  "collection_id": "nevergone-horizontal-control",
  "intervention": {
    "dimension": "action",
    "name": "horizontal_control",
    "baseline_label": "released",
    "treatment_label": "left_pressed",
    "fixed_context_sha256": "<sha256 of the declared fixed context>"
  },
  "observation_window_sha256": "<sha256 of the shared capture-window protocol>",
  "comparisons": [
    {
      "comparison_id": "trial-1",
      "report_path": "trial-1-differential.json",
      "report_sha256": "<sha256 of trial-1-differential.json>"
    },
    {
      "comparison_id": "trial-2",
      "report_path": "trial-2-differential.json",
      "report_sha256": "<sha256 of trial-2-differential.json>"
    },
    {
      "comparison_id": "trial-3",
      "report_path": "trial-3-differential.json",
      "report_sha256": "<sha256 of trial-3-differential.json>"
    }
  ]
}
```

Run the aggregation:

```sh
revenginstr-runtime-intervention intervention-manifest.json \
  --output intervention-evidence.json
```

The unit tests exercise synthetic repeated captures, including a conflicting
trial and an incomplete sample. Synthetic results verify the policy and do not
count as Nevergone runtime evidence. See
[`RUNTIME_DIFFERENTIAL.md`](RUNTIME_DIFFERENTIAL.md) for pairwise report
generation.
