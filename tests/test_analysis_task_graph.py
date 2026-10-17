from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.analysis_task_graph import GRAPH_FORMAT, PLAN_FORMAT, build_invalidation_plan, main

ROOT = Path(__file__).resolve().parents[1]
GRAPH_SCHEMA = json.loads((ROOT / "schemas/analysis-task-graph-v1.schema.json").read_text(encoding="utf-8"))
PLAN_SCHEMA = json.loads((ROOT / "schemas/analysis-invalidation-plan-v1.schema.json").read_text(encoding="utf-8"))


def task(task_id: str, kind: str, *, depends: list[str], inputs: list[str], outputs: list[str]) -> dict:
    return {
        "task_id": task_id,
        "task_kind": kind,
        "configuration_sha256": "a" * 64,
        "depends_on": depends,
        "input_artifacts": inputs,
        "output_artifacts": outputs,
    }


def fixture() -> dict:
    return {
        "format": GRAPH_FORMAT,
        "tasks": [
            task("export_pcode", "pcode_export", depends=[], inputs=["binary"], outputs=["pcode"]),
            task("build_callgraph", "callgraph", depends=["export_pcode"], inputs=["pcode"], outputs=["calls"]),
            task("build_receiver_graph", "receiver_graph", depends=["build_callgraph"], inputs=["calls"], outputs=["receivers"]),
            task("classify", "classification", depends=["export_pcode", "build_receiver_graph"], inputs=["pcode", "receivers"], outputs=["predictions"]),
            task("export_symbols", "symbol_export", depends=[], inputs=["binary"], outputs=["symbols"]),
            task("summarize", "summary", depends=["classify", "export_symbols"], inputs=["predictions", "symbols"], outputs=["summary"]),
        ],
    }


def build(graph: dict, changed: list[str] | None = None) -> dict:
    return build_invalidation_plan(
        graph,
        changed or ["binary"],
        graph_sha256="b" * 64,
    )


def test_invalidation_plan_propagates_source_changes_and_is_deterministic() -> None:
    graph = fixture()
    report = build(graph)

    Draft202012Validator.check_schema(GRAPH_SCHEMA)
    Draft202012Validator(GRAPH_SCHEMA).validate(graph)
    Draft202012Validator.check_schema(PLAN_SCHEMA)
    Draft202012Validator(PLAN_SCHEMA).validate(report)
    assert report["format"] == PLAN_FORMAT
    assert report["topological_order"] == [
        "export_pcode", "build_callgraph", "build_receiver_graph", "classify", "export_symbols", "summarize"
    ]
    assert report["source"] == {
        "graph_sha256": "b" * 64,
        "task_count": 6,
        "artifact_count": 7,
        "source_artifact_count": 1,
    }
    assert [row["task_id"] for row in report["invalidated_tasks"]] == report["topological_order"]
    assert report["invalidated_tasks"][-1]["task_id"] == "summarize"
    assert build(graph) == report


def test_invalidation_plan_handles_changed_intermediate_artifact() -> None:
    report = build(fixture(), ["receivers"])

    assert report["changed_artifact_ids"] == ["receivers"]
    assert [row["task_id"] for row in report["invalidated_tasks"]] == ["classify", "summarize"]
    assert report["invalidated_tasks"][0]["causes"] == [
        {"kind": "changed_input", "artifact_id": "receivers"}
    ]
    assert report["invalidated_tasks"][1]["causes"] == [
        {"kind": "invalidated_dependency", "task_id": "classify"}
    ]


def test_invalidation_plan_does_not_invalidate_producer_for_changed_output() -> None:
    report = build(fixture(), ["predictions"])

    assert [row["task_id"] for row in report["invalidated_tasks"]] == ["summarize"]
    assert report["invalidated_tasks"][0]["causes"] == [
        {"kind": "changed_input", "artifact_id": "predictions"}
    ]


@pytest.mark.parametrize("mutation, message", [
    (lambda graph: graph["tasks"][0].update(depends_on=["missing"]), "unknown dependencies"),
    (lambda graph: graph["tasks"][1].update(depends_on=[]), "missing dependency on producer"),
    (lambda graph: graph["tasks"][0].update(depends_on=["build_callgraph"]), "dependency cycle"),
    (lambda graph: graph["tasks"].append(task("other", "other", depends=[], inputs=[], outputs=["pcode"])), "multiple producer tasks"),
    (lambda graph: graph["tasks"][0].update(task_id=graph["tasks"][1]["task_id"]), "duplicate task_id"),
])
def test_invalid_task_graphs_fail_closed(mutation, message: str) -> None:
    graph = fixture()
    mutation(graph)

    with pytest.raises(ValueError, match=message):
        build(graph)


def test_invalidation_plan_rejects_unknown_or_duplicate_changes() -> None:
    with pytest.raises(ValueError, match="unknown changed artifacts"):
        build(fixture(), ["not_in_graph"])
    with pytest.raises(ValueError, match="unique identifiers"):
        build(fixture(), ["binary", "binary"])


def test_cli_hashes_graph_and_writes_plan(tmp_path: Path, capsys) -> None:
    graph_path = tmp_path / "task-graph.json"
    graph_path.write_text(json.dumps(fixture()), encoding="utf-8")
    output = tmp_path / "nested" / "plan.json"

    assert main([str(graph_path), "--changed-artifact", "binary", "--output", str(output)]) == 0

    report = json.loads(output.read_text(encoding="utf-8"))
    Draft202012Validator(PLAN_SCHEMA).validate(report)
    assert report["source"]["graph_sha256"] == hashlib.sha256(graph_path.read_bytes()).hexdigest()
    assert "invalidated: 6" in capsys.readouterr().out
