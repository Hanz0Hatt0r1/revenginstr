from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.benchmark import BenchmarkError, run_benchmark

ROOT = Path(__file__).resolve().parents[1]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _write_manifest(tmp_path: Path, *, minimum_rows: int = 1) -> Path:
    schema_path = ROOT / "schemas" / "pcode-corpus-v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    corpus_path = tmp_path / "corpus.jsonl"
    corpus_path.write_text(json.dumps({
        "format": "REVENGINSTR.PcodeCorpus/1",
        "program": "sample.bin",
        "source_entry": "00401000",
        "source_name": "FUN_00401000",
        "external": False,
        "decompile_status": "ok",
        "metrics": {"emitted_ops": 1, "truncated": False},
        "model_text": "ARCH=X8632\nPTR_SIZE=4\no0 RETURN\n",
    }) + "\n", encoding="utf-8")
    manifest = {
        "format": "REVENGINSTR.BenchmarkManifest/1",
        "benchmark": {
            "id": "sample-smoke-v1",
            "dataset_id": "synthetic-corpus-v1",
            "dataset_artifact": "corpus",
            "split_id": "smoke",
            "family_set_id": None,
        },
        "toolchain": {"revenginstr_version": "0.5.2", "source_revision": "test"},
        "schemas": {
            "pcode": {
                "path": str(schema_path),
                "version": "REVENGINSTR.PcodeCorpus/1",
                "sha256": _sha256(schema_path),
            }
        },
        "artifacts": {
            "corpus": {
                "path": str(corpus_path), "role": "input", "kind": "file",
                "content": "jsonl", "format": "REVENGINSTR.PcodeCorpus/1",
                "sha256": _sha256(corpus_path), "schema": "pcode",
            },
            "audit": {
                "path": "audit.json", "role": "output", "kind": "file",
                "content": "json", "format": "REVENGINSTR.PcodeAudit/1",
            },
        },
        "configs": {"pcode_audit": {"portable_contract": True}},
        "stages": [{
            "id": "audit",
            "tool": "pcode-audit",
            "args": ["${artifact:corpus}", "--output", "${artifact:audit}"],
            "inputs": ["corpus"],
            "outputs": ["audit"],
        }],
        "metrics": [{
            "name": "corpus_rows", "artifact": "audit",
            "json_pointer": "/corpus/rows", "minimum": minimum_rows,
        }],
    }
    manifest_path = tmp_path / "benchmark.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest_path


def test_benchmark_manifest_and_summary_schemas_are_valid() -> None:
    for filename in ("benchmark-manifest-v1.schema.json", "benchmark-summary-v1.schema.json"):
        schema = json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)


def test_benchmark_runs_a_pinned_smoke_pipeline_and_records_hashes(tmp_path: Path) -> None:
    manifest_path = _write_manifest(tmp_path)
    summary, code = run_benchmark(manifest_path, mode="smoke", output_path=tmp_path / "summary.json")

    assert code == 0
    assert summary["status"] == "passed"
    assert summary["benchmark"]["dataset_id"] == "synthetic-corpus-v1"
    assert summary["stages"][0]["tool"] == "pcode-audit"
    assert summary["metrics"][0]["value"] == 1
    assert summary["metrics"][0]["passed"] is True
    assert summary["artifacts"]["corpus"]["pinned"] is True
    assert summary["artifacts"]["audit"]["pinned"] is False
    assert json.loads((tmp_path / "summary.json").read_text(encoding="utf-8")) == summary


def test_benchmark_fails_a_metric_gate_and_returns_nonzero(tmp_path: Path) -> None:
    manifest_path = _write_manifest(tmp_path, minimum_rows=2)
    summary, code = run_benchmark(manifest_path, output_path=tmp_path / "summary.json")

    assert code == 2
    assert summary["status"] == "failed_gates"
    assert summary["gate_failures"] == ["corpus_rows"]


def test_benchmark_rejects_changed_input_hash_before_running_stages(tmp_path: Path) -> None:
    manifest_path = _write_manifest(tmp_path)
    corpus = tmp_path / "corpus.jsonl"
    corpus.write_text(corpus.read_text(encoding="utf-8") + "\n", encoding="utf-8")

    with pytest.raises(BenchmarkError, match="SHA-256 mismatch"):
        run_benchmark(manifest_path, output_path=tmp_path / "summary.json")
    assert not (tmp_path / "audit.json").exists()


def test_benchmark_rejects_output_overwrite(tmp_path: Path) -> None:
    manifest_path = _write_manifest(tmp_path)
    (tmp_path / "audit.json").write_text("preserve", encoding="utf-8")

    with pytest.raises(BenchmarkError, match="output artifact already exists"):
        run_benchmark(manifest_path)
    assert (tmp_path / "audit.json").read_text(encoding="utf-8") == "preserve"
