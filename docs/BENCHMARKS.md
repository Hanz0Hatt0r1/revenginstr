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

The same contract can chain evidence aggregation, receiver inference,
family-grouped classifier training/inference, router training/inference,
frozen validation and drift audit. Their arguments remain the native CLI
arguments documented by each tool; the benchmark runner only orders, pins,
validates and summarizes them.
