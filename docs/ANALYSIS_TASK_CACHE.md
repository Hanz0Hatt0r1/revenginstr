# Analysis task cache keys

`revenginstr-analysis-task-cache-keys` computes deterministic, content-addressed
keys for every task in an `AnalysisTaskGraph/1`. It does not execute tasks or
claim that any artifact can be reused.

The companion `AnalysisTaskCacheInputs/1` file must provide the SHA-256 for
every source artifact and an implementation SHA-256 for every task. Produced
artifacts are represented by their producer task keys, so a key set can be
computed before those outputs exist. The implementation hash should change
whenever the executable analysis code or runtime contract changes. Missing,
duplicate, or extra identities fail closed.

For a one-task graph that consumes binary and produces pcode, cache inputs are:

    {
      "format": "REVENGINSTR.AnalysisTaskCacheInputs/1",
      "artifact_hashes": [
        {"artifact_id": "binary", "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
      ],
      "task_implementation_hashes": [
        {"task_id": "pcode", "implementation_sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}
      ]
    }

Run it with the same task graph used by the invalidation planner:

    revenginstr-analysis-task-cache-keys task-graph.json cache-inputs.json \
      --output task-cache-key-set.json

Each key binds the task ID and kind, output artifact IDs, configuration hash,
implementation hash, exact source input hashes, and parent task keys. A
changed source/configuration/implementation hash changes its task key and the
keys of downstream tasks; unrelated branches retain their keys. The report
maps each task ID to its key and output artifacts. A caller-managed cache can
use those keys to name one manifest per task and content-addressed objects by
SHA-256:

    cache-root/
      entries/<cache_key_sha256>.json
      objects/<sha256>

Each `AnalysisTaskCacheEntry/1` manifest binds a task ID and cache key to the
exact declared output IDs, each object's SHA-256 and byte size. Artifacts in a
manifest are sorted by ID. The consumer writes and maintains this layout.

Run a read-only lookup for a task:

    revenginstr-analysis-task-cache-lookup task-cache-key-set.json cache-root \
      --task-id pcode --output cache-lookup.json

`AnalysisTaskCacheLookup/1` reports a hit only when the manifest matches the
selected task and all declared objects have the expected byte size and SHA-256.
An absent cache root, entries directory, or task manifest is a miss. Malformed
manifests, mismatched output IDs, symlinked cache paths, and absent or corrupt
objects fail closed. A hit only verifies bytes: the caller must still validate
output schemas and decide whether to use the artifacts. Lookup never restores
files or executes analysis tasks. The cache is caller-managed and this interface
does not authenticate a cache against a malicious writer.

Restore a hit only after supplying a separate `AnalysisTaskCacheRestoreTargets/1`
manifest with an explicit relative destination for every output artifact:

    {
      "format": "REVENGINSTR.AnalysisTaskCacheRestoreTargets/1",
      "task_id": "pcode",
      "cache_key_sha256": "<the task key from the key-set report>",
      "targets": [
        {"artifact_id": "pcode", "relative_path": "exports/pcode.jsonl"}
      ]
    }

    revenginstr-analysis-task-cache-restore task-cache-key-set.json cache-root \
      restore-targets.json --task-id pcode --output-dir run-output \
      --output cache-restore.json

Restore checks the manifest identity, path set, and cache bytes again; accepts
only normalized relative POSIX paths; refuses symlinked output paths and
different existing files; and reports `restored` or `already_present` for each
artifact in `AnalysisTaskCacheRestore/1`. A cache miss does not create the
output directory. Restore only copies verified bytes and never executes cached
analysis or chooses destination paths. Consumers remain responsible for
validating restored output schemas before using them.

Keys are only stable when callers pin every input that affects execution,
including tool/runtime versions and environment-dependent configuration.
Consumers remain responsible for validating cached output schemas and deciding
whether to restore verified artifacts. Task execution, cache eviction,
cost-aware scheduling, and end-to-end consumer convergence remain outside this
interface.
