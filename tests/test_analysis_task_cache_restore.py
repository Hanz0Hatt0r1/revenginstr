from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.analysis_task_cache_lookup import ENTRY_FORMAT
from revenginstr.analysis_task_cache_restore import (
    RESTORE_FORMAT,
    TARGETS_FORMAT,
    main,
    restore_task_cache_entry,
)
from test_analysis_task_cache import build, graph

ROOT = Path(__file__).resolve().parents[1]
TARGETS_SCHEMA = json.loads((ROOT / "schemas/analysis-task-cache-restore-targets-v1.schema.json").read_text())
RESTORE_SCHEMA = json.loads((ROOT / "schemas/analysis-task-cache-restore-v1.schema.json").read_text())
DATA = b"portable p-code fixture\n"


def install_entry(cache_root: Path) -> tuple[dict, dict]:
    task = next(row for row in build()["tasks"] if row["task_id"] == "pcode")
    artifact = {
        "artifact_id": task["output_artifacts"][0],
        "sha256": hashlib.sha256(DATA).hexdigest(),
        "size_bytes": len(DATA),
    }
    manifest = {
        "format": ENTRY_FORMAT,
        "task_id": "pcode",
        "cache_key_sha256": task["cache_key_sha256"],
        "artifacts": [artifact],
    }
    (cache_root / "entries").mkdir(parents=True)
    (cache_root / "objects").mkdir()
    (cache_root / "objects" / artifact["sha256"]).write_bytes(DATA)
    (cache_root / "entries" / f"{task['cache_key_sha256']}.json").write_text(json.dumps(manifest))
    targets = {
        "format": TARGETS_FORMAT,
        "task_id": "pcode",
        "cache_key_sha256": task["cache_key_sha256"],
        "targets": [{"artifact_id": artifact["artifact_id"], "relative_path": "exports/pcode.jsonl"}],
    }
    return targets, manifest


def test_restore_hit_and_idempotent_repeat(tmp_path: Path) -> None:
    cache_root = tmp_path / "cache"
    targets, manifest = install_entry(cache_root)
    Draft202012Validator.check_schema(TARGETS_SCHEMA)
    Draft202012Validator(TARGETS_SCHEMA).validate(targets)

    output_root = tmp_path / "output"
    report = restore_task_cache_entry(build(), "pcode", cache_root, targets, output_root)
    Draft202012Validator.check_schema(RESTORE_SCHEMA)
    Draft202012Validator(RESTORE_SCHEMA).validate(report)
    assert report["format"] == RESTORE_FORMAT
    assert report["status"] == "hit"
    assert report["restored_artifacts"] == [
        {
            "artifact_id": manifest["artifacts"][0]["artifact_id"],
            "relative_path": "exports/pcode.jsonl",
            "sha256": manifest["artifacts"][0]["sha256"],
            "size_bytes": len(DATA),
            "status": "restored",
        }
    ]
    assert (output_root / "exports/pcode.jsonl").read_bytes() == DATA

    repeated = restore_task_cache_entry(build(), "pcode", cache_root, targets, output_root)
    assert repeated["restored_artifacts"][0]["status"] == "already_present"


def test_miss_leaves_output_root_uncreated(tmp_path: Path) -> None:
    key_set = build()
    task = next(row for row in key_set["tasks"] if row["task_id"] == "pcode")
    targets = {
        "format": TARGETS_FORMAT,
        "task_id": "pcode",
        "cache_key_sha256": task["cache_key_sha256"],
        "targets": [{"artifact_id": task["output_artifacts"][0], "relative_path": "exports/pcode.jsonl"}],
    }
    output_root = tmp_path / "output"
    report = restore_task_cache_entry(key_set, "pcode", tmp_path / "absent-cache", targets, output_root)
    Draft202012Validator(RESTORE_SCHEMA).validate(report)
    assert report["status"] == "miss"
    assert report["restored_artifacts"] == []
    assert not output_root.exists()


def test_conflicting_target_is_never_overwritten(tmp_path: Path) -> None:
    cache_root = tmp_path / "cache"
    targets, _ = install_entry(cache_root)
    output = tmp_path / "output" / "exports" / "pcode.jsonl"
    output.parent.mkdir(parents=True)
    output.write_bytes(b"keep this file")

    with pytest.raises(ValueError, match="refusing to overwrite"):
        restore_task_cache_entry(build(), "pcode", cache_root, targets, output.parent.parent)
    assert output.read_bytes() == b"keep this file"


@pytest.mark.parametrize("mutation", ["task", "key", "coverage"])
def test_restore_targets_must_match_task_identity_and_outputs(tmp_path: Path, mutation: str) -> None:
    cache_root = tmp_path / "cache"
    targets, _ = install_entry(cache_root)
    if mutation == "task":
        targets["task_id"] = "symbols"
    elif mutation == "key":
        targets["cache_key_sha256"] = "0" * 64
    else:
        targets["targets"] = []

    with pytest.raises(ValueError, match="identity|exactly cover"):
        restore_task_cache_entry(build(), "pcode", cache_root, targets, tmp_path / "output")


def test_restore_rejects_overlapping_destination_paths(tmp_path: Path) -> None:
    task_graph = graph()
    task_graph["tasks"][0]["output_artifacts"] = ["pcode", "pcode-extra"]
    key_set = build(graph_value=task_graph)
    task = next(row for row in key_set["tasks"] if row["task_id"] == "pcode")
    targets = {
        "format": TARGETS_FORMAT,
        "task_id": "pcode",
        "cache_key_sha256": task["cache_key_sha256"],
        "targets": [
            {"artifact_id": "pcode", "relative_path": "exports"},
            {"artifact_id": "pcode-extra", "relative_path": "exports/nested.jsonl"},
        ],
    }

    with pytest.raises(ValueError, match="must not contain one another"):
        restore_task_cache_entry(key_set, "pcode", tmp_path / "missing-cache", targets, tmp_path / "output")


@pytest.mark.parametrize("relative_path", ["../escape", "/absolute", "a//b", "a\\b", ".", ".."])
def test_restore_rejects_unsafe_paths(tmp_path: Path, relative_path: str) -> None:
    cache_root = tmp_path / "cache"
    targets, _ = install_entry(cache_root)
    targets["targets"][0]["relative_path"] = relative_path
    with pytest.raises(ValueError, match="safe relative POSIX paths"):
        restore_task_cache_entry(build(), "pcode", cache_root, targets, tmp_path / "output")


def test_restore_rejects_symlinked_output_parent(tmp_path: Path) -> None:
    cache_root = tmp_path / "cache"
    targets, _ = install_entry(cache_root)
    output_root = tmp_path / "output"
    output_root.mkdir()
    (output_root / "exports").symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match="must not be a symlink"):
        restore_task_cache_entry(build(), "pcode", cache_root, targets, output_root)


def test_restore_detects_corrupt_cache_object(tmp_path: Path) -> None:
    cache_root = tmp_path / "cache"
    targets, manifest = install_entry(cache_root)
    digest = manifest["artifacts"][0]["sha256"]
    (cache_root / "objects" / digest).write_bytes(b"corrupt")
    with pytest.raises(ValueError, match="integrity check failed"):
        restore_task_cache_entry(build(), "pcode", cache_root, targets, tmp_path / "output")
    assert not (tmp_path / "output").exists()


def test_cli_restores_and_writes_report(tmp_path: Path, capsys) -> None:
    cache_root = tmp_path / "cache"
    targets, _ = install_entry(cache_root)
    keys_path = tmp_path / "keys.json"
    targets_path = tmp_path / "targets.json"
    output_path = tmp_path / "nested" / "report.json"
    keys_path.write_text(json.dumps(build()))
    targets_path.write_text(json.dumps(targets))

    assert main([
        str(keys_path), str(cache_root), str(targets_path), "--task-id", "pcode",
        "--output-dir", str(tmp_path / "restored"), "--output", str(output_path),
    ]) == 0
    report = json.loads(output_path.read_text())
    Draft202012Validator(RESTORE_SCHEMA).validate(report)
    assert report["restored_artifacts"][0]["status"] == "restored"
    assert "cache status: hit" in capsys.readouterr().out


def test_cli_report_cannot_overwrite_an_artifact(tmp_path: Path) -> None:
    cache_root = tmp_path / "cache"
    targets, _ = install_entry(cache_root)
    keys_path = tmp_path / "keys.json"
    targets_path = tmp_path / "targets.json"
    output_root = tmp_path / "restored"
    keys_path.write_text(json.dumps(build()))
    targets_path.write_text(json.dumps(targets))
    report_path = output_root / "exports" / "pcode.jsonl"

    with pytest.raises(ValueError, match="report path must be different"):
        main([
            str(keys_path), str(cache_root), str(targets_path), "--task-id", "pcode",
            "--output-dir", str(output_root), "--output", str(report_path),
        ])
    assert not output_root.exists()
