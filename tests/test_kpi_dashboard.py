from __future__ import annotations

import json
import hashlib
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.kpi_dashboard import FORMAT, MANIFEST_FORMAT, build_dashboard, main


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def make_manifest(tmp_path: Path) -> Path:
    source_path = tmp_path / "source.json"
    write_json(source_path, {
        "format": "REVENGINSTR.BenchmarkSummary/1",
        "metrics": {"precision": 0.975, "coverage": 0.54, "unavailable": None},
        "odd/key~name": 0.75,
    })
    digest = hashlib.sha256(source_path.read_bytes()).hexdigest()
    manifest_path = tmp_path / "dashboard.json"
    write_json(manifest_path, {
        "format": MANIFEST_FORMAT,
        "dashboard": {
            "id": "test-dashboard",
            "title": "Test dashboard",
            "description": "A synthetic metric dashboard.",
        },
        "sources": {
            "candidate": {
                "path": "source.json",
                "sha256": digest,
                "format": "REVENGINSTR.BenchmarkSummary/1",
            },
        },
        "kpis": [
            {"id": "precision", "label": "Accepted precision", "source": "candidate", "json_pointer": "/metrics/precision", "unit": "fraction", "minimum": 0.97},
            {"id": "coverage", "label": "Coverage", "source": "candidate", "json_pointer": "/metrics/coverage", "unit": "fraction", "minimum": 0.55},
            {"id": "unavailable", "label": "Frozen accuracy", "source": "candidate", "json_pointer": "/metrics/unavailable", "unit": "score", "minimum": 0.9},
            {"id": "escaped", "label": "Escaped pointer", "source": "candidate", "json_pointer": "/odd~1key~0name", "unit": "score", "minimum": 0.5},
        ],
    })
    return manifest_path


def validate_schema(name: str, value: dict) -> None:
    schema_path = Path(__file__).resolve().parents[1] / "schemas" / name
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(value)


def test_dashboard_hash_pins_sources_and_reports_targets(tmp_path: Path) -> None:
    manifest_path = make_manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    validate_schema("kpi-dashboard-manifest-v1.schema.json", manifest)
    report, markdown = build_dashboard(manifest_path)

    assert report["format"] == FORMAT
    assert report["status"] == "fail"
    by_id = {row["id"]: row for row in report["kpis"]}
    assert by_id["precision"]["status"] == "pass"
    assert by_id["precision"]["display_value"] == "97.50%"
    assert by_id["coverage"]["status"] == "fail"
    assert by_id["unavailable"]["status"] == "unavailable"
    assert by_id["escaped"]["value"] == 0.75
    assert "| Accepted precision | 97.50% | ≥ 97.00% | PASS | candidate |" in markdown
    assert str(tmp_path) not in json.dumps(report)
    validate_schema("kpi-dashboard-v1.schema.json", report)


def test_dashboard_cli_writes_json_and_markdown(tmp_path: Path) -> None:
    manifest_path = make_manifest(tmp_path)
    json_output = tmp_path / "out/dashboard.json"
    markdown_output = tmp_path / "out/dashboard.md"
    assert main([
        str(manifest_path),
        "--json-output", str(json_output),
        "--markdown-output", str(markdown_output),
    ]) == 0
    assert json.loads(json_output.read_text(encoding="utf-8"))["status"] == "fail"
    assert markdown_output.read_text(encoding="utf-8").startswith("# Test dashboard\n")


def test_dashboard_rejects_source_hash_mismatch(tmp_path: Path) -> None:
    manifest_path = make_manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["sources"]["candidate"]["sha256"] = "0" * 64
    write_json(manifest_path, manifest)
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        build_dashboard(manifest_path)


def test_dashboard_cli_will_not_overwrite_a_source(tmp_path: Path) -> None:
    manifest_path = make_manifest(tmp_path)
    source_path = tmp_path / "source.json"
    original = source_path.read_bytes()
    with pytest.raises(SystemExit) as error:
        main([
            str(manifest_path),
            "--json-output", str(source_path),
            "--markdown-output", str(tmp_path / "out.md"),
        ])
    assert error.value.code == 2
    assert source_path.read_bytes() == original


def test_dashboard_marks_missing_only_metrics_incomplete(tmp_path: Path) -> None:
    manifest_path = make_manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["kpis"] = [manifest["kpis"][2]]
    write_json(manifest_path, manifest)
    report, _ = build_dashboard(manifest_path)
    assert report["status"] == "incomplete"
    assert report["kpis"][0]["status"] == "unavailable"
