from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.benchmark import BenchmarkError, run_benchmark
from revenginstr.benchmark_determinism import _difference_paths, _stable_summary, audit_determinism
from revenginstr.benchmark_metrics import MetricProjectionError, project

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
    assert summary["artifacts"]["corpus"]["size_bytes"] == (tmp_path / "corpus.jsonl").stat().st_size
    assert summary["artifacts"]["audit"]["pinned"] is False
    assert summary["artifacts"]["audit"]["size_bytes"] > 0
    assert summary["stages"][0]["memory_measurement"] in {"getrusage.ru_maxrss", "unavailable"}
    if summary["stages"][0]["memory_measurement"] == "getrusage.ru_maxrss":
        assert summary["stages"][0]["peak_rss_bytes"] > 0
    else:
        assert summary["stages"][0]["peak_rss_bytes"] is None
    assert json.loads((tmp_path / "summary.json").read_text(encoding="utf-8")) == summary


def test_benchmark_runs_receiver_argument_store_flow_stage(tmp_path: Path) -> None:
    manifest_path = _write_manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    argument_path = tmp_path / "argument-roots.tsv"
    argument_path.write_text(
        "format\trow_type\tplan_id\tcallee_entry\tparameter_index\tcaller_entry\t"
        "caller_call_site\tnode_id\tparent_node_id\tdepth\tedge_kind\n"
        "REVENGINSTR.GhidraCallerArgumentSubtree/1\tnode\tplan\t00401000\t0\t"
        "00402000\t00402010\t0\t-1\t0\troot\n",
        encoding="utf-8",
    )
    store_path = tmp_path / "parameter-stores.tsv"
    store_path.write_text(
        "format\tfunction_entry\tstore_address\tstore_time\tdestination_parameter_index\t"
        "destination_offset\tsource_parameter_index\tstatus\n"
        "REVENGINSTR.GhidraParameterStoreField/1\t00401000\t00401020\t7\t0\t"
        "0x24\t1\tparameter_to_parameter_field\n",
        encoding="utf-8",
    )
    graph_schema_path = ROOT / "schemas" / "receiver-provenance-graph-v1.schema.json"
    manifest["schemas"]["receiver_graph"] = {
        "path": str(graph_schema_path), "version": "REVENGINSTR.ReceiverProvenanceGraph/1",
        "sha256": _sha256(graph_schema_path),
    }
    manifest["artifacts"].update({
        "argument_roots": {
            "path": str(argument_path), "role": "input", "kind": "file",
            "content": "tsv", "sha256": _sha256(argument_path),
        },
        "parameter_stores": {
            "path": str(store_path), "role": "input", "kind": "file",
            "content": "tsv", "sha256": _sha256(store_path),
        },
        "joined_graphs": {
            "path": "joined-graphs.jsonl", "role": "output", "kind": "file",
            "content": "jsonl", "format": "REVENGINSTR.ReceiverProvenanceGraph/1",
            "schema": "receiver_graph",
        },
    })
    manifest["stages"].append({
        "id": "argument_store_flow", "tool": "receiver-argument-store-flow",
        "args": [
            "${artifact:argument_roots}", "${artifact:parameter_stores}",
            "--program-id", "analysis:sample", "--output", "${artifact:joined_graphs}",
        ],
        "inputs": ["argument_roots", "parameter_stores"], "outputs": ["joined_graphs"],
    })
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    summary, code = run_benchmark(manifest_path, mode="smoke", output_path=tmp_path / "summary.json")

    assert code == 0
    assert summary["status"] == "passed"
    assert summary["stages"][1]["tool"] == "receiver-argument-store-flow"
    graph = json.loads((tmp_path / "joined-graphs.jsonl").read_text(encoding="utf-8"))
    assert {edge["relation"] for edge in graph["edges"]} == {"argument_flow", "field_store", "data_flow"}


def test_benchmark_runs_receiver_argument_load_flow_stage(tmp_path: Path) -> None:
    manifest_path = _write_manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    argument_path = tmp_path / "argument-roots.tsv"
    argument_path.write_text(
        "format\trow_type\tplan_id\tcallee_entry\tparameter_index\tcaller_entry\t"
        "caller_call_site\tnode_id\tparent_node_id\tdepth\tedge_kind\n"
        "REVENGINSTR.GhidraCallerArgumentSubtree/1\tnode\tplan\t00401000\t0\t"
        "00402000\t00402010\t0\t-1\t0\troot\n",
        encoding="utf-8",
    )
    load_path = tmp_path / "parameter-loads.tsv"
    load_path.write_text(
        "format\tfunction_entry\tload_address\tload_time\tbase_parameter_index\t"
        "field_offset\tvalue_token\tstatus\n"
        "REVENGINSTR.GhidraParameterLoadField/1\t00401000\t00401020\t8\t0\t"
        "0x24\tdef:LOAD@00401020:8:4\tparameter_field_load\n",
        encoding="utf-8",
    )
    graph_schema_path = ROOT / "schemas" / "receiver-provenance-graph-v1.schema.json"
    manifest["schemas"]["receiver_graph"] = {
        "path": str(graph_schema_path), "version": "REVENGINSTR.ReceiverProvenanceGraph/1",
        "sha256": _sha256(graph_schema_path),
    }
    manifest["artifacts"].update({
        "argument_roots": {
            "path": str(argument_path), "role": "input", "kind": "file",
            "content": "tsv", "sha256": _sha256(argument_path),
        },
        "parameter_loads": {
            "path": str(load_path), "role": "input", "kind": "file",
            "content": "tsv", "sha256": _sha256(load_path),
        },
        "joined_graphs": {
            "path": "joined-graphs.jsonl", "role": "output", "kind": "file",
            "content": "jsonl", "format": "REVENGINSTR.ReceiverProvenanceGraph/1",
            "schema": "receiver_graph",
        },
    })
    manifest["stages"].append({
        "id": "argument_load_flow", "tool": "receiver-argument-load-flow",
        "args": [
            "${artifact:argument_roots}", "${artifact:parameter_loads}",
            "--program-id", "analysis:sample", "--output", "${artifact:joined_graphs}",
        ],
        "inputs": ["argument_roots", "parameter_loads"], "outputs": ["joined_graphs"],
    })
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    summary, code = run_benchmark(manifest_path, mode="smoke", output_path=tmp_path / "summary.json")

    assert code == 0
    assert summary["status"] == "passed"
    assert summary["stages"][1]["tool"] == "receiver-argument-load-flow"
    graph = json.loads((tmp_path / "joined-graphs.jsonl").read_text(encoding="utf-8"))
    assert {edge["relation"] for edge in graph["edges"]} == {"argument_flow", "field_load"}


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


def test_classifier_projection_reports_metrics_coverage_and_calibration(tmp_path: Path) -> None:
    predictions = tmp_path / "predictions.jsonl"
    predictions.write_text("".join(json.dumps(row) + "\n" for row in [
        {"truth": "alpha", "prediction": "alpha", "action": "accept", "confidence": 0.9},
        {"truth": "beta", "prediction": "alpha", "action": "review", "confidence": 0.6},
        {"truth": "beta", "prediction": "beta", "action": "accept", "confidence": 0.8},
    ]), encoding="utf-8")

    result = project(
        {"id": "classifier", "kind": "classifier", "artifact": "predictions", "calibration_bins": 2},
        {"content": "jsonl"}, {"predictions": predictions},
    )

    assert result["row_count"] == 3
    assert result["class_distribution"] == {"alpha": 1, "beta": 2}
    assert result["classification"]["confusion_matrix"] == [[1, 0], [1, 1]]
    assert result["classification"]["macro_f1"] == pytest.approx(2 / 3)
    assert result["classification"]["balanced_accuracy"] == pytest.approx(0.75)
    assert result["coverage"]["accepted_rows"] == 2
    assert result["coverage"]["accepted_accuracy"] == 1.0
    assert result["calibration"]["sample_count"] == 3
    assert result["calibration"]["brier_score"] == pytest.approx(0.1366666667)


def test_receiver_projection_exact_evidence_compares_without_emitting_keys(tmp_path: Path) -> None:
    actual = tmp_path / "actual.jsonl"
    expected = tmp_path / "expected.jsonl"
    actual.write_text(json.dumps({"source_id": "opaque-id", "call_index": 7, "status": "resolved_unique_vtable"}) + "\n", encoding="utf-8")
    expected.write_text(json.dumps({"source_id": "opaque-id", "call_index": 7, "status": "unresolved_receiver_class"}) + "\n", encoding="utf-8")

    result = project(
        {
            "id": "receiver", "kind": "receiver", "artifact": "actual",
            "exact_evidence": {
                "expected_artifact": "expected", "key_fields": ["source_id", "call_index"],
                "compare_fields": ["status"], "maximum_mismatches": 0,
            },
        },
        {"content": "jsonl"}, {"actual": actual, "expected": expected},
    )

    assert result["receiver"]["coverage"] == 1.0
    assert result["exact_evidence"]["mismatch_rows"] == 1
    assert result["exact_evidence"]["passed"] is False
    assert "opaque-id" not in json.dumps(result)


def test_receiver_assessment_projection_reports_aggregate_candidate_metrics(tmp_path: Path) -> None:
    assessments = tmp_path / "assessments.jsonl"
    rows = [
        {
            "format": "REVENGINSTR.ReceiverCandidateAssessment/1", "source_id": "private-id",
            "source_entry": "private-entry", "call_index": 1, "call_address": "0x1234",
            "status": "compatible_subtype_candidates", "candidate_receiver_class_names": ["A", "B"],
            "unknown_type_candidate_count": 2, "compatibility_group_id": "private-group",
        },
        {
            "format": "REVENGINSTR.ReceiverCandidateAssessment/1", "source_id": "private-id",
            "source_entry": "private-entry", "call_index": 2, "call_address": None,
            "status": "no_known_candidates", "candidate_receiver_class_names": [],
            "unknown_type_candidate_count": 0, "compatibility_group_id": None,
        },
    ]
    assessments.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")

    result = project(
        {"id": "receiver-assessment", "kind": "receiver_assessment", "artifact": "assessments"},
        {"content": "jsonl"}, {"assessments": assessments},
    )

    assert result["row_count"] == 2
    assert result["receiver_assessment"] == {
        "status_counts": {"compatible_subtype_candidates": 1, "no_known_candidates": 1},
        "candidate_count_counts": {"0": 1, "2": 1},
        "rows_with_unknown_candidates": 1,
        "unknown_candidate_total": 2,
        "compatibility_group_rows": 1,
    }
    summary_text = json.dumps(result)
    for private_value in ("private-id", "private-entry", "private-group", "0x1234", '"A"'):
        assert private_value not in summary_text


def test_receiver_assessment_projection_rejects_invalid_status(tmp_path: Path) -> None:
    assessments = tmp_path / "assessments.jsonl"
    assessments.write_text(json.dumps({
        "format": "REVENGINSTR.ReceiverCandidateAssessment/1", "status": "maybe",
    }) + "\n", encoding="utf-8")
    with pytest.raises(MetricProjectionError, match="invalid candidate status"):
        project(
            {"id": "receiver-assessment", "kind": "receiver_assessment", "artifact": "assessments"},
            {"content": "jsonl"}, {"assessments": assessments},
        )


def test_receiver_candidate_evidence_projection_aggregates_dimensions_without_ids(tmp_path: Path) -> None:
    dimensions = (
        "exact_vtable_witness", "constructor_factory_witness", "field_layout_compatibility",
        "slot_compatibility", "caller_provenance", "callgraph_consistency", "runtime_witness",
    )
    row = {
        "format": "REVENGINSTR.ReceiverCandidateEvidence/1", "source_id": "private-source",
        "source_entry": "private-entry", "call_index": 4, "call_address": "0x1234",
        "candidate_id": "private-candidate",
        "dimensions": {
            name: {"status": "unknown", "evidence_class": None, "provenance": []}
            for name in dimensions
        },
    }
    row["dimensions"]["exact_vtable_witness"] = {
        "status": "supported", "evidence_class": "exact_static",
        "provenance": [{"source_format": "private-source-format/1", "source_id": "private-row"}],
    }
    path = tmp_path / "candidate-evidence.jsonl"
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")

    result = project(
        {"id": "candidate-evidence", "kind": "receiver_candidate_evidence", "artifact": "evidence"},
        {"content": "jsonl"}, {"evidence": path},
    )

    metrics = result["receiver_candidate_evidence"]["dimension_metrics"]
    assert metrics["exact_vtable_witness"] == {
        "status_counts": {"supported": 1}, "evidence_class_counts": {"exact_static": 1},
    }
    assert metrics["runtime_witness"] == {
        "status_counts": {"unknown": 1}, "evidence_class_counts": {},
    }
    for private_value in ("private-source", "private-entry", "private-candidate", "private-row", "0x1234"):
        assert private_value not in json.dumps(result)


def test_receiver_candidate_evidence_projection_rejects_unproven_support(tmp_path: Path) -> None:
    dimensions = (
        "exact_vtable_witness", "constructor_factory_witness", "field_layout_compatibility",
        "slot_compatibility", "caller_provenance", "callgraph_consistency", "runtime_witness",
    )
    row = {
        "format": "REVENGINSTR.ReceiverCandidateEvidence/1",
        "dimensions": {
            name: {"status": "unknown", "evidence_class": None, "provenance": []}
            for name in dimensions
        },
    }
    row["dimensions"]["exact_vtable_witness"] = {
        "status": "supported", "evidence_class": "exact_static", "provenance": [],
    }
    path = tmp_path / "candidate-evidence.jsonl"
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")

    with pytest.raises(MetricProjectionError, match="incomplete exact_vtable_witness evidence"):
        project(
            {"id": "candidate-evidence", "kind": "receiver_candidate_evidence", "artifact": "evidence"},
            {"content": "jsonl"}, {"evidence": path},
        )


def test_benchmark_runs_projections_and_fails_exact_evidence_gate(tmp_path: Path) -> None:
    manifest_path = _write_manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    rows = {
        "predictions": [{"truth": "alpha", "prediction": "alpha", "action": "accept", "confidence": 0.9}],
        "receiver_actual": [{"key": "opaque", "status": "resolved_unique_vtable"}],
        "receiver_expected": [{"key": "opaque", "status": "unresolved_receiver_class"}],
        "receiver_assessment": [{
            "format": "REVENGINSTR.ReceiverCandidateAssessment/1", "status": "mixed_candidates",
            "candidate_receiver_class_names": ["TypeA", "TypeB"], "unknown_type_candidate_count": 1,
            "compatibility_group_id": None,
        }],
        "candidate_evidence": [{
            "format": "REVENGINSTR.ReceiverCandidateEvidence/1",
            "dimensions": {
                name: {"status": "unknown", "evidence_class": None, "provenance": []}
                for name in (
                    "exact_vtable_witness", "constructor_factory_witness", "field_layout_compatibility",
                    "slot_compatibility", "caller_provenance", "callgraph_consistency", "runtime_witness",
                )
            },
        }],
    }
    for artifact_id, records in rows.items():
        artifact_path = tmp_path / f"{artifact_id}.jsonl"
        artifact_path.write_text("".join(json.dumps(row) + "\n" for row in records), encoding="utf-8")
        manifest["artifacts"][artifact_id] = {
            "path": str(artifact_path), "role": "input", "kind": "file", "content": "jsonl",
            "sha256": _sha256(artifact_path),
        }
    drift_path = tmp_path / "drift.json"
    drift_path.write_text(json.dumps({"format": "REVENGINSTR.DriftAudit/1", "labels_available": False,
                                     "reference_rows": 20, "frozen_rows": 10}), encoding="utf-8")
    manifest["artifacts"]["drift"] = {
        "path": str(drift_path), "role": "input", "kind": "file", "content": "json",
        "sha256": _sha256(drift_path),
    }
    manifest["projections"] = [
        {"id": "classifier", "kind": "classifier", "artifact": "predictions"},
        {
            "id": "receiver", "kind": "receiver", "artifact": "receiver_actual",
            "exact_evidence": {
                "expected_artifact": "receiver_expected", "key_fields": ["key"],
                "compare_fields": ["status"], "maximum_mismatches": 0,
            },
        },
        {"id": "drift", "kind": "validation", "artifact": "drift"},
        {"id": "receiver-assessment", "kind": "receiver_assessment", "artifact": "receiver_assessment"},
        {"id": "candidate-evidence", "kind": "receiver_candidate_evidence", "artifact": "candidate_evidence"},
    ]
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    summary, code = run_benchmark(manifest_path, output_path=tmp_path / "summary-with-projections.json")

    assert code == 2
    assert summary["status"] == "failed_gates"
    assert summary["gate_failures"] == ["receiver.exact_evidence_mismatches"]
    assert summary["projections"][0]["classification"]["macro_f1"] == 1.0
    assert summary["projections"][1]["exact_evidence"]["mismatch_rows"] == 1
    assert summary["projections"][2]["validation"]["labels_available"] is False
    assert summary["projections"][2]["validation"]["frozen_rows"] == 10
    assert summary["projections"][3]["receiver_assessment"]["unknown_candidate_total"] == 1
    assert summary["projections"][4]["receiver_candidate_evidence"]["dimension_metrics"]["runtime_witness"]["status_counts"] == {"unknown": 1}


def test_validation_projection_preserves_unlabeled_status(tmp_path: Path) -> None:
    report = tmp_path / "drift.json"
    report.write_text(json.dumps({
        "format": "REVENGINSTR.DriftAudit/1", "labels_available": False,
        "reference_rows": 20, "frozen_rows": 10,
        "severity": {"level": "moderate"},
        "router_intervention": {"reference_legacy_accept": 8, "reference_changed": 1},
    }), encoding="utf-8")

    result = project(
        {"id": "drift", "kind": "validation", "artifact": "report"},
        {"content": "json"}, {"report": report},
    )

    assert result["validation"]["labels_available"] is False
    assert result["validation"]["reference_rows"] == 20
    assert result["validation"]["frozen_rows"] == 10
    assert result["validation"]["severity"] == "moderate"
    assert "classification" not in result


def test_determinism_audit_replays_pinned_pipeline_without_touching_outputs(tmp_path: Path) -> None:
    manifest_path = _write_manifest(tmp_path)
    report_path = tmp_path / "determinism.json"

    report, code = audit_determinism(manifest_path, mode="smoke", output_path=report_path)

    assert code == 0
    assert report["status"] == "deterministic"
    assert report["deterministic"] is True
    assert report["difference_paths"] == []
    assert len(report["runs"]) == 2
    assert report["runs"][0]["artifact_sha256"] == report["runs"][1]["artifact_sha256"]
    assert not (tmp_path / "audit.json").exists()
    Draft202012Validator(json.loads((ROOT / "schemas" / "determinism-audit-v1.schema.json").read_text(encoding="utf-8"))).validate(report)


def test_determinism_comparison_ignores_runtime_but_finds_metric_drift() -> None:
    first = {"stages": [{"id": "audit", "duration_seconds": 0.1, "peak_rss_bytes": 1000}], "metrics": [{"value": 4}]}
    second = {"stages": [{"id": "audit", "duration_seconds": 0.2, "peak_rss_bytes": 2000}], "metrics": [{"value": 4}]}

    assert _difference_paths(_stable_summary(first), _stable_summary(second)) == []
    second["metrics"][0]["value"] = 5
    assert _difference_paths(_stable_summary(first), _stable_summary(second)) == ["/metrics/0/value"]
