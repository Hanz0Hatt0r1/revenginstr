"""Restore verified analysis task outputs without executing cached tasks."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tempfile
from pathlib import Path, PurePosixPath
from typing import Any

from revenginstr.analysis_task_cache_lookup import _task_key, lookup_task_cache_entry

TARGETS_FORMAT = "REVENGINSTR.AnalysisTaskCacheRestoreTargets/1"
RESTORE_FORMAT = "REVENGINSTR.AnalysisTaskCacheRestore/1"
_SAFE_RELATIVE_PATH = re.compile(r"^[A-Za-z0-9_-][A-Za-z0-9_.-]*(?:/[A-Za-z0-9_-][A-Za-z0-9_.-]*)*$")


def _relative_path(value: Any) -> str:
    if not isinstance(value, str) or _SAFE_RELATIVE_PATH.fullmatch(value) is None:
        raise ValueError("restore target paths must be safe relative POSIX paths")
    path = PurePosixPath(value)
    if path.is_absolute() or value != path.as_posix() or any(part in {".", ".."} for part in path.parts):
        raise ValueError("restore target paths must be normalized and stay within the output directory")
    return value


def _validate_targets(cache_key_set: Any, task_id: str, targets: Any) -> tuple[dict[str, Any], dict[str, str]]:
    task = _task_key(cache_key_set, task_id)
    if (
        not isinstance(targets, dict)
        or set(targets) != {"format", "task_id", "cache_key_sha256", "targets"}
        or targets.get("format") != TARGETS_FORMAT
        or targets.get("task_id") != task_id
        or targets.get("cache_key_sha256") != task["cache_key_sha256"]
        or not isinstance(targets.get("targets"), list)
    ):
        raise ValueError("restore target manifest identity or fields do not match the task")

    rows = targets["targets"]
    artifact_ids: list[str] = []
    paths: list[str] = []
    mapping: dict[str, str] = {}
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"artifact_id", "relative_path"}:
            raise ValueError("invalid restore target record")
        artifact_id, relative_path = row["artifact_id"], _relative_path(row["relative_path"])
        if not isinstance(artifact_id, str) or artifact_id not in task["output_artifacts"]:
            raise ValueError("restore target contains an undeclared output artifact")
        artifact_ids.append(artifact_id)
        paths.append(relative_path)
        mapping[artifact_id] = relative_path
    if artifact_ids != sorted(set(artifact_ids)) or artifact_ids != task["output_artifacts"]:
        raise ValueError("restore targets must exactly cover task outputs in unique sorted order")
    if len(paths) != len(set(paths)):
        raise ValueError("restore target paths must be unique")
    path_set = set(paths)
    if any(parent.as_posix() in path_set for path in paths for parent in PurePosixPath(path).parents):
        raise ValueError("restore target paths must not contain one another")
    return task, mapping


def _ensure_directory(path: Path) -> Path:
    path = Path(os.path.abspath(path))
    for directory in reversed(path.parents):
        if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
            raise ValueError(f"output directory path is not a real directory: {directory}")
    missing: list[Path] = []
    current = path
    while not current.exists():
        if current.is_symlink():
            raise ValueError(f"output directory path is a symlink: {current}")
        missing.append(current)
        current = current.parent
    if current.is_symlink() or not current.is_dir():
        raise ValueError(f"output directory path is not a real directory: {current}")
    for directory in reversed(missing):
        directory.mkdir()
        if directory.is_symlink() or not directory.is_dir():
            raise ValueError(f"output directory path changed while creating it: {directory}")
    if path.is_symlink() or not path.is_dir():
        raise ValueError(f"output directory path is not a real directory: {path}")
    return path


def _ensure_target_parent(root: Path, relative_path: str) -> Path:
    parent = root
    for part in PurePosixPath(relative_path).parts[:-1]:
        parent = parent / part
        if parent.is_symlink():
            raise ValueError(f"restore target parent must not be a symlink: {relative_path}")
        if parent.exists():
            if not parent.is_dir():
                raise ValueError(f"restore target parent is not a directory: {relative_path}")
        else:
            parent.mkdir()
            if parent.is_symlink() or not parent.is_dir():
                raise ValueError(f"restore target parent changed while creating it: {relative_path}")
    return parent


def _file_matches(path: Path, artifact: dict[str, Any]) -> bool:
    if path.is_symlink():
        raise ValueError(f"restore target must not be a symlink: {path.name}")
    if not path.exists():
        return False
    if not path.is_file():
        raise ValueError(f"restore target is not a regular file: {path.name}")
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    if size != artifact["size_bytes"] or digest.hexdigest() != artifact["sha256"]:
        raise ValueError(f"refusing to overwrite a different existing restore target: {path.name}")
    return True


def _stage_object(source: Path, destination: Path, artifact: dict[str, Any]) -> None:
    if source.is_symlink() or not source.is_file():
        raise ValueError(f"cache object is missing or invalid: {artifact['sha256']}")
    digest = hashlib.sha256()
    size = 0
    with source.open("rb") as input_file, destination.open("xb") as output_file:
        for chunk in iter(lambda: input_file.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
            output_file.write(chunk)
        output_file.flush()
        os.fsync(output_file.fileno())
    if size != artifact["size_bytes"] or digest.hexdigest() != artifact["sha256"]:
        destination.unlink(missing_ok=True)
        raise ValueError(f"cache object integrity check failed: {artifact['sha256']}")
    destination.chmod(0o644)


def restore_task_cache_entry(
    cache_key_set: Any,
    task_id: str,
    cache_root: Path,
    restore_targets: Any,
    output_root: Path,
) -> dict[str, Any]:
    """Restore a verified cache hit to explicit, safe, non-overwriting targets."""
    task, target_paths = _validate_targets(cache_key_set, task_id, restore_targets)
    lookup = lookup_task_cache_entry(cache_key_set, task_id, cache_root)
    result = {
        "format": RESTORE_FORMAT,
        "task_id": task_id,
        "cache_key_sha256": task["cache_key_sha256"],
        "status": lookup["status"],
        "reason": lookup["reason"],
        "restored_artifacts": [],
    }
    if lookup["status"] == "miss" or not lookup["verified_artifacts"]:
        return result

    root = _ensure_directory(output_root)
    planned = []
    for artifact in lookup["verified_artifacts"]:
        relative_path = target_paths[artifact["artifact_id"]]
        parent = _ensure_target_parent(root, relative_path)
        destination = parent / PurePosixPath(relative_path).name
        already_present = _file_matches(destination, artifact)
        planned.append((artifact, relative_path, destination, already_present))

    pending = [(artifact, relative_path, destination) for artifact, relative_path, destination, present in planned if not present]
    created: list[tuple[Path, int, int]] = []
    with tempfile.TemporaryDirectory(prefix=".revenginstr-cache-restore-", dir=root) as staging_text:
        staging = Path(staging_text)
        staged: dict[str, Path] = {}
        for index, (artifact, _, _) in enumerate(pending):
            staged_path = staging / str(index)
            _stage_object(Path(cache_root) / "objects" / artifact["sha256"], staged_path, artifact)
            staged[artifact["artifact_id"]] = staged_path
        try:
            for artifact, relative_path, destination in pending:
                if destination.is_symlink() or destination.exists():
                    raise ValueError(f"restore target appeared during restore: {relative_path}")
                os.link(staged[artifact["artifact_id"]], destination)
                info = destination.lstat()
                created.append((destination, info.st_dev, info.st_ino))
        except Exception:
            for destination, device, inode in reversed(created):
                try:
                    info = destination.lstat()
                    if stat.S_ISREG(info.st_mode) and (info.st_dev, info.st_ino) == (device, inode):
                        destination.unlink()
                except FileNotFoundError:
                    pass
            raise

    statuses = {
        artifact["artifact_id"]: "already_present" if present else "restored"
        for artifact, _, _, present in planned
    }
    result["restored_artifacts"] = [
        {
            "artifact_id": artifact["artifact_id"],
            "relative_path": relative_path,
            "sha256": artifact["sha256"],
            "size_bytes": artifact["size_bytes"],
            "status": statuses[artifact["artifact_id"]],
        }
        for artifact, relative_path, _, _ in planned
    ]
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cache_key_set_json", type=Path)
    parser.add_argument("cache_root", type=Path)
    parser.add_argument("restore_targets_json", type=Path)
    parser.add_argument("--task-id", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)

    cache_key_set = json.loads(args.cache_key_set_json.read_bytes())
    targets = json.loads(args.restore_targets_json.read_bytes())
    _, target_paths = _validate_targets(cache_key_set, args.task_id, targets)
    report_path = args.output.resolve()
    output_root = Path(os.path.abspath(args.output_dir))
    destinations = [(output_root.joinpath(*PurePosixPath(path).parts)).resolve() for path in target_paths.values()]
    if any(os.path.normcase(report_path) == os.path.normcase(path) for path in destinations):
        raise ValueError("restore report path must be different from every artifact destination")
    if args.output.exists() and any(path.exists() and os.path.samefile(args.output, path) for path in destinations):
        raise ValueError("restore report path must not be a hard link to an artifact destination")

    report = restore_task_cache_entry(
        cache_key_set,
        args.task_id,
        args.cache_root,
        targets,
        args.output_dir,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("cache status:", report["status"])
    print("restored artifacts:", len(report["restored_artifacts"]))
    print("output:", args.output)
    return 0
