# Reproducible benchmarks

`revenginstr-benchmark` runs a project-neutral pipeline from a versioned JSON
manifest. Consumer datasets, family assignments, labels and evidence stay in the
consumer repository; the manifest pins their IDs and SHA-256 hashes without
copying them into `revenginstr`.

Install the runner and its JSON Schema validator with:

```bash
python -m pip install -e '.[benchmark]'
```

For manifests that run classifier or router stages, install `.[benchmark,ml]`.

## Manifest outline

The `REVENGINSTR.BenchmarkManifest/1` schema is
[`schemas/benchmark-manifest-v1.schema.json`](../schemas/benchmark-manifest-v1.schema.json).
It records the dataset, split and family-set identities, toolchain versions,
schema versions and hashes, artifact paths and hashes, stage configurations,
and metric gates. JSON, JSONL, CSV and TSV artifacts can be checked against a
declared JSON Schema. Every schema is itself hash-pinned.
The manifest's `revenginstr_version` must match the installed package version.

Paths are relative to the manifest unless absolute. Input file and directory
artifacts require a SHA-256. Directory hashes are deterministic over sorted
relative file names and file contents; symlinks are rejected. Output artifacts
must not exist before the run. Use fresh output paths for each run.

Stages form an ordered dependency graph. The runner accepts only the tools
listed by the manifest schema, passes arguments without a shell, and expands
exact `${artifact:NAME}` arguments to resolved artifact paths. Every declared
stage input/output must appear as an artifact argument. The selected stage set
is controlled by `--mode smoke` or `--mode full`; stages marked `both` run in
either mode. A stage that consumes another stage's output must depend on its
producer.
Pass file and directory arguments through artifact placeholders so they resolve
consistently even though tools run from the `revenginstr` installation directory.

Metric gates point into JSON summary artifacts with JSON Pointers. A missing,
non-finite or non-numeric metric fails the gate. A run writes a
`REVENGINSTR.BenchmarkSummary/1` JSON file with the manifest hash, toolchain and
schema versions, artifact hashes, executed commands, runtimes, metric values
and gate results. Stage failures and gate failures return exit status 2.

## Standard metric projections

Optional manifest `projections` turn existing classifier, router, receiver and
validation artifacts into comparable summary sections. Projections read rows
from consumer-owned JSONL/JSON artifacts; the shared runner stores aggregate
counts and metrics, not prediction rows or evidence identities. Classifier and
router rows use `truth`, `prediction`, `action` and `confidence` by default.
Set `truth_field`, `prediction_field`, `action_field` or `confidence_field` when
a consumer uses different column names. Classification projections report the
true-label distribution, per-class precision/recall/F1, macro-F1, balanced
accuracy, confusion matrix, action coverage and calibration bins. Calibration
uses confidence as a probability of correctness and only scores rows with both
labels and confidence.

A report may omit execution stages when it summarizes already-produced frozen
artifacts. Such manifests must still declare at least one projection or metric;
the ordinary input hash and schema checks still apply.

Receiver projections count statuses and compute coverage over statuses named
in `resolved_statuses` (default: `resolved_unique_vtable`). `reason_fields` can
map available OOD, conflict and failure reason columns into count maps; absent
reason data is not inferred. A validation projection summarizes frozen
selection or drift reports without treating unlabeled rows as accuracy.

For a frozen function-level denominator, a receiver projection may also name a
JSONL `population_artifact` and `function_id_field` (default: `source_id`). The
population must contain unique identities, and every receiver query must join
to one of them. The summary reports query-level resolution separately from
the fraction of population functions with any receiver query and with a
resolved query; identities are never copied into the summary.

`receiver_assessment` projections accept `ReceiverCandidateAssessment/1`
JSONL and report status counts, candidate-count distribution, rows and total
unknown typed candidates, and rows with a consumer-declared compatibility
group. These are descriptive counts, not correctness or routing metrics. The
optional `exact_evidence` gate can compare candidate assessments to sealed
consumer expectations while keeping record identities and values out of the
summary.

`receiver_candidate_evidence` projections accept `ReceiverCandidateEvidence/1`
and report status and evidence-class counts separately for each dimension.
They do not combine correlated evidence into a score. Consumer artifacts
should pin the candidate-evidence schema in the manifest; exact comparisons can
use consumer-chosen identity keys without copying them into the summary.

An optional `exact_evidence` block compares actual and expected JSONL records by
consumer-chosen key fields and compares only the listed evidence fields. The
summary contains compared/mismatched/missing/unexpected row counts, never the
keys or row values. `maximum_mismatches` defaults to zero and becomes a hard
benchmark gate.

Example:

```json
{
  "projections": [
    {
      "id": "classifier_oof",
      "kind": "classifier",
      "artifact": "oof_predictions",
      "calibration_bins": 10,
      "reason_fields": {
        "ood": "ood_reason",
        "conflict": "conflict_reason",
        "failure": "failure_reason"
      }
    },
    {
      "id": "receiver_exact",
      "kind": "receiver",
      "artifact": "receiver_inference",
      "exact_evidence": {
        "expected_artifact": "receiver_expected",
        "key_fields": ["source_id", "call_index"],
        "compare_fields": ["status", "receiver_vtable_id"],
        "maximum_mismatches": 0
      }
    },
    {
      "id": "receiver_candidate_assessment",
      "kind": "receiver_assessment",
      "artifact": "receiver_candidate_assessments",
      "exact_evidence": {
        "expected_artifact": "receiver_candidate_assessments_expected",
        "key_fields": ["source_id", "call_index"],
        "compare_fields": ["status", "candidate_receiver_class_names"],
        "maximum_mismatches": 0
      }
    },
    {
      "id": "receiver_candidate_evidence",
      "kind": "receiver_candidate_evidence",
      "artifact": "receiver_candidate_evidence"
    }
  ]
}
```

Artifact summaries include byte sizes. Stage summaries include elapsed time and
peak process RSS where the platform exposes it through `getrusage`; the memory
value is `null` with measurement `unavailable` on unsupported platforms.

## Determinism audit

`revenginstr-determinism-audit` runs the selected smoke/full stage set twice
with identical pinned inputs and isolated temporary output paths. It compares
artifact hashes (including row-selection traces and predictions), metric and
projection values, benchmark configuration, manifests, and stage results. The
report lists JSON Pointers for differences and hashes for each run. Stage
duration and peak RSS are excluded because they vary between executions. The
consumer manifest and its declared artifact paths are not modified.

```bash
revenginstr-determinism-audit benchmark.json --mode smoke --output build/determinism.json
```

The command requires stage file paths to use `${artifact:ID}` placeholders so
the runner can safely redirect outputs for both repetitions. It returns 0 when
the stable summaries match and 2 when they differ or a run fails.

## Consumer CI and metric deltas

The reusable workflow at
`.github/workflows/consumer-benchmark.yml` runs in the calling consumer
repository. That keeps benchmark manifests, labels, datasets and result
artifacts with their owner; `revenginstr` receives only the generic runner code.
The consumer workflow passes a manifest path; it defaults to `revenginstr`'s
`main` branch, but should pin a reviewed commit or tag for reproducible runs. It
uploads candidate summaries (and optional deltas) as artifacts of the consumer's
Actions run.

Example consumer workflow:

```yaml
name: Frozen benchmark
on:
  workflow_dispatch:
jobs:
  benchmark:
    uses: Hanz0Hatt0r1/revenginstr/.github/workflows/consumer-benchmark.yml@main
    with:
      manifest_path: benchmarks/frozen/manifest.json
      baseline_summary_path: benchmarks/frozen/baseline-summary.json
      mode: full
      revenginstr_ref: main
```

For behavior-changing PRs, pass the retained baseline summary path to generate a
machine-readable metric delta. The baseline and candidate must share mode,
dataset, split and family-set identities. `revenginstr-benchmark-delta`
compares numeric manifest gates, class metrics, confusion counts, coverage,
calibration, receiver status/coverage and candidate-assessment distributions,
reason counts, candidate evidence states by dimension, and exact-evidence
counts. It reports
added/removed metrics with a null value on the missing side. Attach the consumer
workflow artifact or its delta JSON to the PR; do not copy consumer data into
this repository.

## Small corpus-audit manifest

This example shows the fields for an input corpus and one audit stage. Replace
the dataset path and hash with consumer-owned values. Get the schema hash with
`sha256sum schemas/pcode-corpus-v1.schema.json`.

```json
{
  "format": "REVENGINSTR.BenchmarkManifest/1",
  "benchmark": {
    "id": "example-smoke-v1",
    "dataset_id": "consumer-corpus-v1",
    "dataset_artifact": "corpus",
    "split_id": "smoke",
    "family_set_id": null
  },
  "toolchain": {"revenginstr_version": "0.5.2"},
  "schemas": {
    "pcode": {
      "path": "schemas/pcode-corpus-v1.schema.json",
      "version": "REVENGINSTR.PcodeCorpus/1",
      "sha256": "<64-character schema SHA-256>"
    }
  },
  "artifacts": {
    "corpus": {
      "path": "data/corpus.jsonl",
      "role": "input",
      "kind": "file",
      "content": "jsonl",
      "format": "REVENGINSTR.PcodeCorpus/1",
      "sha256": "<64-character corpus SHA-256>",
      "schema": "pcode"
    },
    "audit": {
      "path": "build/audit.json",
      "role": "output",
      "kind": "file",
      "content": "json",
      "format": "REVENGINSTR.PcodeAudit/1"
    }
  },
  "configs": {"pcode_audit": {"portable_contract": true}},
  "stages": [
    {
      "id": "audit",
      "tool": "pcode-audit",
      "args": ["${artifact:corpus}", "--output", "${artifact:audit}"],
      "inputs": ["corpus"],
      "outputs": ["audit"]
    }
  ],
  "metrics": [
    {"name": "corpus_rows", "artifact": "audit", "json_pointer": "/corpus/rows", "minimum": 1}
  ]
}
```

Run the full manifest (or the smoke subset):

```bash
revenginstr-benchmark benchmark.json --mode full --output build/summary.json
```

The same contract can chain evidence aggregation, receiver inference and
provenance graph construction (including bounded caller-argument/store joins),
family-grouped classifier training/inference, router training/inference,
frozen validation and drift audit. Their arguments remain the native CLI
arguments documented by each tool; the benchmark runner only orders, pins,
validates and summarizes them.
