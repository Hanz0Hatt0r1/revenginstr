"""Verify caller-managed content-addressed analysis cache entries."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from revenginstr.analysis_task_cache import KEY_SET_FORMAT, _task_cache_key_sha256
from revenginstr.analysis_task_graph import _ID, _KIND, _SHA256

ENTRY_FORMAT = "REVENGINSTR.AnalysisTaskCacheEntry/1"
LOOKUP_FORMAT = "REVENGINSTR.AnalysisTaskCacheLookup/1"
_TASK_KEY_FIELDS = {
    "task_id", "task_kind", "configuration_sha256", "implementation_sha256",
    "input_artifact_hashes", "dependency_cache_keys", "output_artifacts", "cache_key_sha256",
}


def _task_key(cache_key_set: Any, task_id: str) -> dict[str, Any]:
    if not isinstance(cache_key_set, dict) or cache_key_set.get("format") != KEY_SET_FORMAT:
        raise ValueError("unsupported analysis task cache key set")
    rows = cache_key_set.get("tasks")
    if not isinstance(rows, list):
        raise ValueError("cache key set must contain a task array")
    row_ids = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("cache key set tasks must be objects")
        row_id = row.get("task_id")
        if not isinstance(row_id, str) or _ID.fullmatch(row_id) is None:
            raise ValueError("cache key set task ids must be valid identifiers")
        row_ids.append(row_id)
    if len(row_ids) != len(set(row_ids)):
        raise ValueError("cache key set task ids must be unique")
    matches = [row for row in rows if isinstance(row, dict) and row.get("task_id") == task_id]
    if len(matches) != 1:
        raise ValueError(f"expected exactly one cache key for task {task_id!r}")

    row = matches[0]
    if set(row) != _TASK_KEY_FIELDS:
        raise ValueError(f"task {task_id!r}: unexpected cache key fields")
    if not isinstance(task_id, str) or _ID.fullmatch(task_id) is None:
        raise ValueError("invalid task id")
    if not isinstance(row["task_kind"], str) or _KIND.fullmatch(row["task_kind"]) is None:
        raise ValueError("invalid task kind")
    for field in ("configuration_sha256", "implementation_sha256", "cache_key_sha256"):
        if not isinstance(row[field], str) or _SHA256.fullmatch(row[field]) is None:
            raise ValueError(f"invalid {field}")

    inputs = row["input_artifact_hashes"]
    if not isinstance(inputs, list):
        raise ValueError("input_artifact_hashes must be an array")
    input_ids = []
    for item in inputs:
        if not isinstance(item, dict) or set(item) != {"artifact_id", "sha256"}:
            raise ValueError("invalid input artifact hash record")
        if not isinstance(item["artifact_id"], str) or _ID.fullmatch(item["artifact_id"]) is None:
            raise ValueError("invalid input artifact id")
        if not isinstance(item["sha256"], str) or _SHA256.fullmatch(item["sha256"]) is None:
            raise ValueError("invalid input artifact SHA-256")
        input_ids.append(item["artifact_id"])
    if input_ids != sorted(set(input_ids)):
        raise ValueError("input artifact hashes must be uniquely sorted")

    dependencies = row["dependency_cache_keys"]
    if not isinstance(dependencies, list):
        raise ValueError("dependency_cache_keys must be an array")
    dependency_ids = []
    for item in dependencies:
        if not isinstance(item, dict) or set(item) != {"task_id", "cache_key_sha256"}:
            raise ValueError("invalid dependency cache key")
        if not isinstance(item["task_id"], str) or _ID.fullmatch(item["task_id"]) is None:
            raise ValueError("invalid dependency task id")
        if not isinstance(item["cache_key_sha256"], str) or _SHA256.fullmatch(item["cache_key_sha256"]) is None:
            raise ValueError("invalid dependency cache key SHA-256")
        dependency_ids.append(item["task_id"])
    if dependency_ids != sorted(set(dependency_ids)):
        raise ValueError("dependency cache keys must be uniquely sorted")

    outputs = row["output_artifacts"]
    if (
        not isinstance(outputs, list)
        or any(not isinstance(item, str) or _ID.fullmatch(item) is None for item in outputs)
        or outputs != sorted(set(outputs))
    ):
        raise ValueError("output artifacts must be uniquely sorted identifiers")
    if _task_cache_key_sha256(row) != row["cache_key_sha256"]:
        raise ValueError(f"task {task_id!r}: cache key does not match its key material")
    return row


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def lookup_task_cache_entry(
    cache_key_set: Any,
    task_id: str,
    cache_root: Path,
) -> dict[str, Any]:
    """Verify a task's manifest and content-addressed outputs; never restore them."""
    task = _task_key(cache_key_set, task_id)
    cache_key = task["cache_key_sha256"]
    root = Path(cache_root)
    if root.is_symlink():
        raise ValueError("cache root must not be a symlink")
    if not root.exists():
        return {
            "format": LOOKUP_FORMAT,
            "task_id": task_id,
            "cache_key_sha256": cache_key,
            "status": "miss",
            "reason": "entry_missing",
            "verified_artifacts": [],
        }
    if not root.is_dir():
        raise ValueError("cache root is not a directory")
    entries = root / "entries"
    if entries.is_symlink():
        raise ValueError("cache entries directory must not be a symlink")
    if not entries.exists():
        return {
            "format": LOOKUP_FORMAT,
            "task_id": task_id,
            "cache_key_sha256": cache_key,
            "status": "miss",
            "reason": "entry_missing",
            "verified_artifacts": [],
        }
    if not entries.is_dir():
        raise ValueError("cache entries path is not a directory")
    manifest_path = entries / f"{cache_key}.json"
    if manifest_path.is_symlink():
        raise ValueError("cache entry manifest must not be a symlink")
    if not manifest_path.exists():
        return {
            "format": LOOKUP_FORMAT,
            "task_id": task_id,
            "cache_key_sha256": cache_key,
            "status": "miss",
            "reason": "entry_missing",
            "verified_artifacts": [],
        }
    if not manifest_path.is_file():
        raise ValueError("cache entry manifest is not a regular file")

    try:
        manifest = json.loads(manifest_path.read_bytes())
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("cache entry manifest is not valid JSON") from exc
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"format", "task_id", "cache_key_sha256", "artifacts"}
        or manifest.get("format") != ENTRY_FORMAT
        or manifest.get("task_id") != task_id
        or manifest.get("cache_key_sha256") != cache_key
        or not isinstance(manifest.get("artifacts"), list)
    ):
        raise ValueError("cache entry manifest identity or fields do not match the task")

    artifacts = manifest["artifacts"]
    artifact_ids = []
    for artifact in artifacts:
        if not isinstance(artifact, dict) or set(artifact) != {"artifact_id", "sha256", "size_bytes"}:
            raise ValueError("invalid cache entry artifact record")
        artifact_id, digest, size = artifact["artifact_id"], artifact["sha256"], artifact["size_bytes"]
        if not isinstance(artifact_id, str) or _ID.fullmatch(artifact_id) is None:
            raise ValueError("invalid cache entry artifact id")
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            raise ValueError("invalid cache entry artifact SHA-256")
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise ValueError("invalid cache entry artifact size")
        artifact_ids.append(artifact_id)
    if artifact_ids != sorted(set(artifact_ids)) or artifact_ids != task["output_artifacts"]:
        raise ValueError("cache entry artifacts do not exactly match task outputs")

    verified = []
    if artifacts:
        objects = root / "objects"
        if objects.is_symlink() or not objects.is_dir():
            raise ValueError("cache objects directory is missing or invalid")
        for artifact in artifacts:
            blob = objects / artifact["sha256"]
            if blob.is_symlink() or not blob.is_file():
                raise ValueError(f"cache object is missing or invalid: {artifact['sha256']}")
            size = blob.stat().st_size
            if size != artifact["size_bytes"] or _sha256_file(blob) != artifact["sha256"]:
                raise ValueError(f"cache object integrity check failed: {artifact['sha256']}")
            verified.append(dict(artifact))

    return {
        "format": LOOKUP_FORMAT,
        "task_id": task_id,
        "cache_key_sha256": cache_key,
        "status": "hit",
        "reason": None,
        "verified_artifacts": verified,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cache_key_set_json", type=Path)
    parser.add_argument("cache_root", type=Path)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)

    report = lookup_task_cache_entry(
        json.loads(args.cache_key_set_json.read_bytes()), args.task_id, args.cache_root
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("cache status:", report["status"])
    print("verified artifacts:", len(report["verified_artifacts"]))
    print("output:", args.output)
    return 0
