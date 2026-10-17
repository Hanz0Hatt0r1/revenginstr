from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.analysis_task_cache import (
    INPUTS_FORMAT,
    KEY_SET_FORMAT,
    build_task_cache_key_set,
    main,
)
from revenginstr.analysis_task_graph import GRAPH_FORMAT

ROOT = Path(__file__).resolve().parents[1]
INPUT_SCHEMA = json.loads((ROOT / "schemas/analysis-task-cache-inputs-v1.schema.json").read_text())
REPORT_SCHEMA = json.loads((ROOT / "schemas/analysis-task-cache-key-set-v1.schema.json").read_text())


def task(task_id: str, kind: str, *, inputs: list[str], outputs: list[str], depends: list[str]) -> dict:
    return {
        "task_id": task_id,
        "task_kind": kind,
        "configuration_sha256": hashlib.sha256(task_id.encode()).hexdigest(),
        "depends_on": depends,
        "input_artifacts": inputs,
        "output_artifacts": outputs,
    }


def graph() -> dict:
    return {
        "format": GRAPH_FORMAT,
        "tasks": [
            task("pcode", "pcode_export", inputs=["binary"], outputs=["pcode"], depends=[]),
            task("callgraph", "callgraph", inputs=["pcode"], outputs=["calls"], depends=["pcode"]),
            task("symbols", "symbol_export", inputs=["binary"], outputs=["symbols"], depends=[]),
            task("summary", "summary", inputs=["calls", "symbols"], outputs=["report"], depends=["callgraph", "symbols"]),
        ],
    }


def cache_inputs() -> dict:
    artifact_ids = ["binary"]
    task_ids = ["pcode", "callgraph", "symbols", "summary"]
    return {
        "format": INPUTS_FORMAT,
        "artifact_hashes": [{"artifact_id": item, "sha256": (str(i + 1) * 64)} for i, item in enumerate(artifact_ids)],
        "task_implementation_hashes": [
            {"task_id": item, "implementation_sha256": (str(i + 1) * 64)}
            for i, item in enumerate(task_ids)
        ],
    }


def build(graph_value: dict | None = None, inputs_value: dict | None = None) -> dict:
    return build_task_cache_key_set(
        graph() if graph_value is None else graph_value,
        cache_inputs() if inputs_value is None else inputs_value,
        graph_sha256="a" * 64,
        cache_inputs_sha256="b" * 64,
    )


def key_by_task(report: dict) -> dict[str, str]:
    return {row["task_id"]: row["cache_key_sha256"] for row in report["tasks"]}


def test_cache_key_set_is_deterministic_and_schema_valid() -> None:
    inputs = cache_inputs()
    report = build(inputs_value=inputs)
    reordered = cache_inputs()
    reordered["artifact_hashes"].reverse()
    reordered["task_implementation_hashes"].reverse()

    Draft202012Validator.check_schema(INPUT_SCHEMA)
    Draft202012Validator(INPUT_SCHEMA).validate(inputs)
    Draft202012Validator.check_schema(REPORT_SCHEMA)
    Draft202012Validator(REPORT_SCHEMA).validate(report)
    assert report["format"] == KEY_SET_FORMAT
    assert report["topological_order"] == ["pcode", "callgraph", "symbols", "summary"]
    assert key_by_task(report) == key_by_task(build(inputs_value=reordered))
    assert build() == report


def test_source_config_implementation_and_dependency_changes_change_keys() -> None:
    baseline = key_by_task(build())

    changed_artifact = cache_inputs()
    changed_artifact["artifact_hashes"][0]["sha256"] = "f" * 64
    changed = key_by_task(build(inputs_value=changed_artifact))
    assert changed["pcode"] != baseline["pcode"]
    assert changed["callgraph"] != baseline["callgraph"]
    assert changed["symbols"] != baseline["symbols"]
    assert changed["summary"] != baseline["summary"]

    changed_implementation = cache_inputs()
    changed_implementation["task_implementation_hashes"][0]["implementation_sha256"] = "f" * 64
    changed = key_by_task(build(inputs_value=changed_implementation))
    assert changed["pcode"] != baseline["pcode"]
    assert changed["summary"] != baseline["summary"]

    changed_config = graph()
    changed_config["tasks"][1]["configuration_sha256"] = "f" * 64
    changed = key_by_task(build(graph_value=changed_config))
    assert changed["callgraph"] != baseline["callgraph"]
    assert changed["summary"] != baseline["summary"]
    assert changed["symbols"] == baseline["symbols"]


@pytest.mark.parametrize("mutation, message", [
    (lambda inputs: inputs["artifact_hashes"].pop(), "exactly cover source artifacts"),
    (lambda inputs: inputs["artifact_hashes"].append({"artifact_id": "unknown", "sha256": "f" * 64}), "exactly cover source artifacts"),
    (lambda inputs: inputs["artifact_hashes"].append({"artifact_id": "pcode", "sha256": "f" * 64}), "exactly cover source artifacts"),
    (lambda inputs: inputs["artifact_hashes"].append(inputs["artifact_hashes"][0]), "duplicate artifact_id"),
    (lambda inputs: inputs["task_implementation_hashes"].pop(), "exactly cover graph tasks"),
    (lambda inputs: inputs["task_implementation_hashes"].append({"task_id": "unknown", "implementation_sha256": "f" * 64}), "exactly cover graph tasks"),
])
def test_cache_inputs_must_pin_every_graph_artifact_and_task(mutation, message: str) -> None:
    inputs = cache_inputs()
    mutation(inputs)
    with pytest.raises(ValueError, match=message):
        build(inputs_value=inputs)


def test_cli_hashes_inputs_and_writes_report(tmp_path: Path, capsys) -> None:
    graph_path = tmp_path / "task-graph.json"
    inputs_path = tmp_path / "cache-inputs.json"
    output_path = tmp_path / "nested" / "cache-key-set.json"
    graph_bytes = json.dumps(graph()).encode()
    inputs_bytes = json.dumps(cache_inputs()).encode()
    graph_path.write_bytes(graph_bytes)
    inputs_path.write_bytes(inputs_bytes)

    assert main([str(graph_path), str(inputs_path), "--output", str(output_path)]) == 0

    report = json.loads(output_path.read_text())
    Draft202012Validator(REPORT_SCHEMA).validate(report)
    assert report["source"]["task_graph_sha256"] == hashlib.sha256(graph_bytes).hexdigest()
    assert report["source"]["cache_inputs_sha256"] == hashlib.sha256(inputs_bytes).hexdigest()
    assert "cache keys: 4" in capsys.readouterr().out
