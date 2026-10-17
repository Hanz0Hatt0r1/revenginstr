# Analysis task cache keys

`revenginstr-analysis-task-cache-keys` computes deterministic, content-addressed
keys for every task in an `AnalysisTaskGraph/1`. It does not execute tasks,
inspect a cache, or claim that any artifact can be reused.

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
maps each task ID to its key and output artifacts so a consumer can compare it
with its own cache manifest.

Keys are only stable when callers pin every input that affects execution,
including tool/runtime versions and environment-dependent configuration.
Consumers remain responsible for validating cached output bytes and schemas on
restore. Persistent cache lookup, artifact restoration, and task execution are
outside this interface.
