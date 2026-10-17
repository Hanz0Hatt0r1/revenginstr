"""Validate bounded analysis dependencies and plan downstream invalidation."""
from __future__ import annotations

import argparse
import hashlib
import heapq
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

GRAPH_FORMAT = "REVENGINSTR.AnalysisTaskGraph/1"
PLAN_FORMAT = "REVENGINSTR.AnalysisInvalidationPlan/1"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]*$")
_KIND = re.compile(r"^[a-z][a-z0-9_]*$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_TASK_FIELDS = {
    "task_id", "task_kind", "configuration_sha256", "depends_on",
    "input_artifacts", "output_artifacts",
}


def _identifiers(value: Any, *, where: str, allow_empty: bool) -> list[str]:
    if (
        not isinstance(value, list)
        or (not allow_empty and not value)
        or any(not isinstance(item, str) or _ID.fullmatch(item) is None for item in value)
        or len(value) != len(set(value))
    ):
        qualifier = "" if allow_empty else "non-empty "
        raise ValueError(f"{where}: expected a {qualifier}array of unique identifiers")
    return value


def _validate_graph(graph: Any) -> tuple[dict[str, dict[str, Any]], dict[str, str], list[str], set[str]]:
    if not isinstance(graph, dict) or set(graph) != {"format", "tasks"} or graph.get("format") != GRAPH_FORMAT:
        raise ValueError("unsupported analysis task graph format or fields")
    raw_tasks = graph.get("tasks")
    if not isinstance(raw_tasks, list) or not raw_tasks:
        raise ValueError("analysis task graph must contain at least one task")

    tasks: dict[str, dict[str, Any]] = {}
    producer: dict[str, str] = {}
    inputs_seen: set[str] = set()
    for index, task in enumerate(raw_tasks, 1):
        where = f"task {index}"
        if not isinstance(task, dict) or set(task) != _TASK_FIELDS:
            raise ValueError(f"{where}: unexpected fields")
        task_id = task["task_id"]
        if not isinstance(task_id, str) or _ID.fullmatch(task_id) is None or task_id in tasks:
            raise ValueError(f"{where}: invalid or duplicate task_id")
        kind = task["task_kind"]
        if not isinstance(kind, str) or _KIND.fullmatch(kind) is None:
            raise ValueError(f"{where}: invalid task_kind")
        config_hash = task["configuration_sha256"]
        if not isinstance(config_hash, str) or _SHA256.fullmatch(config_hash) is None:
            raise ValueError(f"{where}: invalid configuration SHA-256")
        depends_on = _identifiers(task["depends_on"], where=f"{where} depends_on", allow_empty=True)
        input_artifacts = _identifiers(task["input_artifacts"], where=f"{where} input_artifacts", allow_empty=True)
        output_artifacts = _identifiers(task["output_artifacts"], where=f"{where} output_artifacts", allow_empty=True)
        if task_id in depends_on:
            raise ValueError(f"task {task_id!r}: self-dependency")
        if set(input_artifacts) & set(output_artifacts):
            raise ValueError(f"task {task_id!r}: cannot read an artifact it also produces")
        for artifact_id in output_artifacts:
            if artifact_id in producer:
                raise ValueError(f"artifact {artifact_id!r}: multiple producer tasks")
            producer[artifact_id] = task_id
        inputs_seen.update(input_artifacts)
        tasks[task_id] = {
            "task_kind": kind,
            "configuration_sha256": config_hash,
            "depends_on": depends_on,
            "input_artifacts": input_artifacts,
            "output_artifacts": output_artifacts,
        }

    for task_id, task in tasks.items():
        unknown = set(task["depends_on"]) - tasks.keys()
        if unknown:
            raise ValueError(f"task {task_id!r}: unknown dependencies {sorted(unknown)}")
        for artifact_id in task["input_artifacts"]:
            producer_id = producer.get(artifact_id)
            if producer_id == task_id:
                raise ValueError(f"task {task_id!r}: reads its own output artifact {artifact_id!r}")
            if producer_id is not None and producer_id not in task["depends_on"]:
                raise ValueError(
                    f"task {task_id!r}: missing dependency on producer {producer_id!r} "
                    f"for artifact {artifact_id!r}"
                )

    dependents: dict[str, set[str]] = defaultdict(set)
    indegree = {task_id: len(task["depends_on"]) for task_id, task in tasks.items()}
    for task_id, task in tasks.items():
        for dependency in task["depends_on"]:
            dependents[dependency].add(task_id)
    ready = [task_id for task_id, degree in indegree.items() if degree == 0]
    heapq.heapify(ready)
    order = []
    while ready:
        task_id = heapq.heappop(ready)
        order.append(task_id)
        for dependent in sorted(dependents[task_id]):
            indegree[dependent] -= 1
            if indegree[dependent] == 0:
                heapq.heappush(ready, dependent)
    if len(order) != len(tasks):
        cyclic = sorted(task_id for task_id, degree in indegree.items() if degree)
        raise ValueError(f"analysis task graph contains a dependency cycle: {cyclic}")

    source_artifacts = inputs_seen - producer.keys()
    return tasks, producer, order, source_artifacts


def build_invalidation_plan(
    graph: dict[str, Any],
    changed_artifact_ids: list[str],
    *,
    graph_sha256: str,
) -> dict[str, Any]:
    """Return tasks invalidated by changed artifact contents, in stable order."""
    if not isinstance(graph_sha256, str) or _SHA256.fullmatch(graph_sha256) is None:
        raise ValueError("invalid task graph SHA-256")
    tasks, producer, order, source_artifacts = _validate_graph(graph)
    changed = _identifiers(changed_artifact_ids, where="changed_artifact_ids", allow_empty=False)
    known_artifacts = source_artifacts | set(producer)
    unknown = set(changed) - known_artifacts
    if unknown:
        raise ValueError(f"unknown changed artifacts: {sorted(unknown)}")

    invalidated: set[str] = set()
    invalidated_rows = []
    for task_id in order:
        task = tasks[task_id]
        changed_inputs = sorted(set(task["input_artifacts"]) & set(changed))
        invalidated_dependencies = sorted(set(task["depends_on"]) & invalidated)
        causes = [
            {"kind": "changed_input", "artifact_id": artifact_id}
            for artifact_id in changed_inputs
        ] + [
            {"kind": "invalidated_dependency", "task_id": dependency}
            for dependency in invalidated_dependencies
        ]
        if causes:
            invalidated.add(task_id)
            invalidated_rows.append({"task_id": task_id, "causes": causes})

    return {
        "format": PLAN_FORMAT,
        "source": {
            "graph_sha256": graph_sha256,
            "task_count": len(tasks),
            "artifact_count": len(known_artifacts),
            "source_artifact_count": len(source_artifacts),
        },
        "changed_artifact_ids": sorted(changed),
        "topological_order": order,
        "invalidated_tasks": invalidated_rows,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("task_graph_json", type=Path)
    parser.add_argument("--changed-artifact", action="append", required=True, dest="changed_artifact_ids")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    graph_bytes = args.task_graph_json.read_bytes()
    graph = json.loads(graph_bytes)
    plan = build_invalidation_plan(
        graph,
        args.changed_artifact_ids,
        graph_sha256=hashlib.sha256(graph_bytes).hexdigest(),
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(plan, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("tasks:", plan["source"]["task_count"])
    print("invalidated:", len(plan["invalidated_tasks"]))
    print("output:", args.output)
    return 0
