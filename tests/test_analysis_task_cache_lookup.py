from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.analysis_task_cache_lookup import (
    ENTRY_FORMAT,
    LOOKUP_FORMAT,
    lookup_task_cache_entry,
    main,
)
from test_analysis_task_cache import build

ROOT = Path(__file__).resolve().parents[1]
ENTRY_SCHEMA = json.loads((ROOT / "schemas/analysis-task-cache-entry-v1.schema.json").read_text())
LOOKUP_SCHEMA = json.loads((ROOT / "schemas/analysis-task-cache-lookup-v1.schema.json").read_text())


def install_entry(cache_root: Path, *, task_id: str = "pcode") -> dict:
    task = next(row for row in build()["tasks"] if row["task_id"] == task_id)
    artifact_id = task["output_artifacts"][0]
    data = b"portable p-code fixture\n"
    digest = hashlib.sha256(data).hexdigest()
    artifact = {"artifact_id": artifact_id, "sha256": digest, "size_bytes": len(data)}
    manifest = {
        "format": ENTRY_FORMAT,
        "task_id": task_id,
        "cache_key_sha256": task["cache_key_sha256"],
        "artifacts": [artifact],
    }
    (cache_root / "entries").mkdir(parents=True)
    (cache_root / "objects").mkdir()
    (cache_root / "objects" / digest).write_bytes(data)
    (cache_root / "entries" / f"{task['cache_key_sha256']}.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )
    return manifest


def test_lookup_verifies_entry_and_content_addressed_output(tmp_path: Path) -> None:
    cache_root = tmp_path / "cache"
    manifest = install_entry(cache_root)

    Draft202012Validator.check_schema(ENTRY_SCHEMA)
    Draft202012Validator(ENTRY_SCHEMA).validate(manifest)
    report = lookup_task_cache_entry(build(), "pcode", cache_root)
    Draft202012Validator.check_schema(LOOKUP_SCHEMA)
    Draft202012Validator(LOOKUP_SCHEMA).validate(report)
    assert report == {
        "format": LOOKUP_FORMAT,
        "task_id": "pcode",
        "cache_key_sha256": manifest["cache_key_sha256"],
        "status": "hit",
        "reason": None,
        "verified_artifacts": manifest["artifacts"],
    }


@pytest.mark.parametrize("cache_root_kind", ["absent", "empty", "entries_only"])
def test_absent_cache_entry_is_a_miss(tmp_path: Path, cache_root_kind: str) -> None:
    cache_root = tmp_path / "cache"
    if cache_root_kind != "absent":
        cache_root.mkdir()
    if cache_root_kind == "entries_only":
        (cache_root / "entries").mkdir()

    report = lookup_task_cache_entry(build(), "pcode", cache_root)
    Draft202012Validator(LOOKUP_SCHEMA).validate(report)
    assert report["status"] == "miss"
    assert report["reason"] == "entry_missing"
    assert report["verified_artifacts"] == []


def test_manifest_must_cover_exact_declared_outputs(tmp_path: Path) -> None:
    cache_root = tmp_path / "cache"
    manifest = install_entry(cache_root)
    manifest["artifacts"] = []
    (cache_root / "entries" / f"{manifest['cache_key_sha256']}.json").write_text(
        json.dumps(manifest), encoding="utf-8"
    )

    with pytest.raises(ValueError, match="exactly match task outputs"):
        lookup_task_cache_entry(build(), "pcode", cache_root)


@pytest.mark.parametrize("corruption", ["missing", "wrong_bytes", "wrong_size"])
def test_object_integrity_must_match_manifest(tmp_path: Path, corruption: str) -> None:
    cache_root = tmp_path / "cache"
    manifest = install_entry(cache_root)
    artifact = manifest["artifacts"][0]
    blob = cache_root / "objects" / artifact["sha256"]
    if corruption == "missing":
        blob.unlink()
    elif corruption == "wrong_bytes":
        blob.write_bytes(b"tampered p-code")
    else:
        artifact["size_bytes"] += 1
        (cache_root / "entries" / f"{manifest['cache_key_sha256']}.json").write_text(
            json.dumps(manifest), encoding="utf-8"
        )

    with pytest.raises(ValueError, match="cache object|integrity check"):
        lookup_task_cache_entry(build(), "pcode", cache_root)


def test_lookup_rejects_tampered_task_key_material(tmp_path: Path) -> None:
    cache_root = tmp_path / "cache"
    install_entry(cache_root)
    key_set = build()
    task = next(row for row in key_set["tasks"] if row["task_id"] == "pcode")
    task["configuration_sha256"] = "f" * 64

    with pytest.raises(ValueError, match="cache key does not match"):
        lookup_task_cache_entry(key_set, "pcode", cache_root)


def test_lookup_rejects_symlinked_cache_paths(tmp_path: Path) -> None:
    actual = tmp_path / "actual"
    actual.mkdir()
    link = tmp_path / "cache"
    link.symlink_to(actual, target_is_directory=True)

    with pytest.raises(ValueError, match="cache root must not be a symlink"):
        lookup_task_cache_entry(build(), "pcode", link)


def test_cli_writes_schema_valid_hit_and_miss_reports(tmp_path: Path, capsys) -> None:
    key_set_path = tmp_path / "keys.json"
    key_set_path.write_text(json.dumps(build()), encoding="utf-8")
    cache_root = tmp_path / "cache"
    install_entry(cache_root)
    hit_output = tmp_path / "hit.json"
    miss_output = tmp_path / "miss.json"

    assert main([str(key_set_path), str(cache_root), "--task-id", "pcode", "--output", str(hit_output)]) == 0
    empty_cache = tmp_path / "empty-cache"
    empty_cache.mkdir()
    assert main([str(key_set_path), str(empty_cache), "--task-id", "pcode", "--output", str(miss_output)]) == 0

    hit = json.loads(hit_output.read_text())
    miss = json.loads(miss_output.read_text())
    Draft202012Validator(LOOKUP_SCHEMA).validate(hit)
    Draft202012Validator(LOOKUP_SCHEMA).validate(miss)
    assert hit["status"] == "hit"
    assert miss["status"] == "miss"
    assert "cache status: hit" in capsys.readouterr().out
