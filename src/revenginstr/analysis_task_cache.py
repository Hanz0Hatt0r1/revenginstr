"""Build deterministic content keys for a bounded analysis task graph."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from revenginstr.analysis_task_graph import _ID, _SHA256, _validate_graph

INPUTS_FORMAT = "REVENGINSTR.AnalysisTaskCacheInputs/1"
KEY_SET_FORMAT = "REVENGINSTR.AnalysisTaskCacheKeySet/1"
KEY_FORMAT = "REVENGINSTR.AnalysisTaskCacheKey/1"


def _hash_records(
    records: Any,
    *,
    id_field: str,
    hash_field: str,
    where: str,
    allow_empty: bool,
) -> dict[str, str]:
    if not isinstance(records, list) or (not allow_empty and not records):
        qualifier = "possibly empty" if allow_empty else "non-empty"
        raise ValueError(f"{where}: expected a {qualifier} array")
    result: dict[str, str] = {}
    for index, row in enumerate(records, 1):
        label = f"{where} record {index}"
        if not isinstance(row, dict) or set(row) != {id_field, hash_field}:
            raise ValueError(f"{label}: unexpected fields")
        identifier, digest = row[id_field], row[hash_field]
        if not isinstance(identifier, str) or _ID.fullmatch(identifier) is None or identifier in result:
            raise ValueError(f"{label}: invalid or duplicate {id_field}")
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            raise ValueError(f"{label}: invalid SHA-256")
        result[identifier] = digest
    return result


def _validate_inputs(
    graph: dict[str, Any], cache_inputs: Any
) -> tuple[dict[str, str], dict[str, str], dict[str, dict[str, Any]], list[str], set[str], int]:
    if (
        not isinstance(cache_inputs, dict)
        or set(cache_inputs) != {"format", "artifact_hashes", "task_implementation_hashes"}
        or cache_inputs.get("format") != INPUTS_FORMAT
    ):
        raise ValueError("unsupported analysis task cache inputs format or fields")

    tasks, producer, order, source_artifacts = _validate_graph(graph)
    graph_artifact_count = len(source_artifacts | set(producer))
    artifact_hashes = _hash_records(
        cache_inputs["artifact_hashes"], id_field="artifact_id", hash_field="sha256",
        where="artifact_hashes", allow_empty=True,
    )
    implementation_hashes = _hash_records(
        cache_inputs["task_implementation_hashes"], id_field="task_id",
        hash_field="implementation_sha256", where="task_implementation_hashes", allow_empty=False,
    )
    if set(artifact_hashes) != source_artifacts:
        missing = sorted(source_artifacts - artifact_hashes.keys())
        unknown = sorted(artifact_hashes.keys() - source_artifacts)
        raise ValueError(f"artifact hashes must exactly cover source artifacts; missing={missing}, unknown={unknown}")
    if set(implementation_hashes) != tasks.keys():
        missing = sorted(tasks.keys() - implementation_hashes.keys())
        unknown = sorted(implementation_hashes.keys() - tasks.keys())
        raise ValueError(f"implementation hashes must exactly cover graph tasks; missing={missing}, unknown={unknown}")
    return artifact_hashes, implementation_hashes, tasks, order, source_artifacts, graph_artifact_count


def build_task_cache_key_set(
    graph: dict[str, Any],
    cache_inputs: Any,
    *,
    graph_sha256: str,
    cache_inputs_sha256: str,
) -> dict[str, Any]:
    """Return stable per-task keys; do not inspect or execute a cache."""
    for label, digest in (("task graph", graph_sha256), ("cache inputs", cache_inputs_sha256)):
        if not isinstance(digest, str) or _SHA256.fullmatch(digest) is None:
            raise ValueError(f"invalid {label} SHA-256")

    artifact_hashes, implementation_hashes, tasks, order, source_artifacts, graph_artifact_count = _validate_inputs(
        graph, cache_inputs
    )
    cache_keys: dict[str, str] = {}
    rows = []
    for task_id in order:
        task = tasks[task_id]
        inputs = [
            {"artifact_id": artifact_id, "sha256": artifact_hashes[artifact_id]}
            for artifact_id in sorted(set(task["input_artifacts"]) & source_artifacts)
        ]
        dependencies = [
            {"task_id": dependency, "cache_key_sha256": cache_keys[dependency]}
            for dependency in sorted(task["depends_on"])
        ]
        key_material = {
            "format": KEY_FORMAT,
            "task_id": task_id,
            "task_kind": task["task_kind"],
            "configuration_sha256": task["configuration_sha256"],
            "implementation_sha256": implementation_hashes[task_id],
            "input_artifact_hashes": inputs,
            "dependency_cache_keys": dependencies,
            "output_artifacts": sorted(task["output_artifacts"]),
        }
        key_bytes = json.dumps(key_material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        cache_key = hashlib.sha256(key_bytes).hexdigest()
        cache_keys[task_id] = cache_key
        rows.append({
            "task_id": task_id,
            "task_kind": task["task_kind"],
            "configuration_sha256": task["configuration_sha256"],
            "implementation_sha256": implementation_hashes[task_id],
            "input_artifact_hashes": inputs,
            "dependency_cache_keys": dependencies,
            "output_artifacts": sorted(task["output_artifacts"]),
            "cache_key_sha256": cache_key,
        })

    return {
        "format": KEY_SET_FORMAT,
        "source": {
            "task_graph_sha256": graph_sha256,
            "cache_inputs_sha256": cache_inputs_sha256,
            "task_count": len(tasks),
            "artifact_count": graph_artifact_count,
            "source_artifact_count": len(source_artifacts),
        },
        "topological_order": order,
        "tasks": rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("task_graph_json", type=Path)
    parser.add_argument("cache_inputs_json", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    graph_bytes = args.task_graph_json.read_bytes()
    cache_inputs_bytes = args.cache_inputs_json.read_bytes()
    report = build_task_cache_key_set(
        json.loads(graph_bytes),
        json.loads(cache_inputs_bytes),
        graph_sha256=hashlib.sha256(graph_bytes).hexdigest(),
        cache_inputs_sha256=hashlib.sha256(cache_inputs_bytes).hexdigest(),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("tasks:", report["source"]["task_count"])
    print("cache keys:", len(report["tasks"]))
    print("output:", args.output)
    return 0
