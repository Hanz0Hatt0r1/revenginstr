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


def test_benchmark_runs_receiver_field_access_pair_stage(tmp_path: Path) -> None:
    manifest_path = _write_manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    store_path = tmp_path / "parameter-stores.tsv"
    store_path.write_text(
        "format\tfunction_entry\tstore_address\tstore_time\tdestination_parameter_index\t"
        "destination_offset\tsource_parameter_index\tstatus\n"
        "REVENGINSTR.GhidraParameterStoreField/1\t00401000\t00401020\t7\t0\t"
        "0x24\t1\tparameter_to_parameter_field\n",
        encoding="utf-8",
    )
    load_path = tmp_path / "parameter-loads.tsv"
    load_path.write_text(
        "format\tfunction_entry\tload_address\tload_time\tbase_parameter_index\t"
        "field_offset\tvalue_token\tstatus\n"
        "REVENGINSTR.GhidraParameterLoadField/1\t00401000\t00401030\t8\t0\t"
        "0x24\tdef:LOAD@00401030:8:4\tparameter_field_load\n",
        encoding="utf-8",
    )
    graph_schema_path = ROOT / "schemas" / "receiver-provenance-graph-v1.schema.json"
    manifest["schemas"]["receiver_graph"] = {
        "path": str(graph_schema_path), "version": "REVENGINSTR.ReceiverProvenanceGraph/1",
        "sha256": _sha256(graph_schema_path),
    }
    manifest["artifacts"].update({
        "parameter_stores": {
            "path": str(store_path), "role": "input", "kind": "file",
            "content": "tsv", "sha256": _sha256(store_path),
        },
        "parameter_loads": {
            "path": str(load_path), "role": "input", "kind": "file",
            "content": "tsv", "sha256": _sha256(load_path),
        },
        "paired_graphs": {
            "path": "paired-graphs.jsonl", "role": "output", "kind": "file",
            "content": "jsonl", "format": "REVENGINSTR.ReceiverProvenanceGraph/1",
            "schema": "receiver_graph",
        },
    })
    manifest["stages"].append({
        "id": "field_access_pairs", "tool": "receiver-field-access-pairs",
        "args": [
            "${artifact:parameter_stores}", "${artifact:parameter_loads}",
            "--program-id", "analysis:sample", "--output", "${artifact:paired_graphs}",
        ],
        "inputs": ["parameter_stores", "parameter_loads"], "outputs": ["paired_graphs"],
    })
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    summary, code = run_benchmark(manifest_path, mode="smoke", output_path=tmp_path / "summary.json")

    assert code == 0
    assert summary["status"] == "passed"
    assert summary["stages"][1]["tool"] == "receiver-field-access-pairs"
    graph = json.loads((tmp_path / "paired-graphs.jsonl").read_text(encoding="utf-8"))
    assert {edge["relation"] for edge in graph["edges"]} == {
        "field_store", "data_flow", "field_load"
    }


def test_benchmark_runs_parameter_load_return_flow_stage(tmp_path: Path) -> None:
    manifest_path = _write_manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    load_path = tmp_path / "parameter-loads.tsv"
    load_path.write_text(
        "format\tfunction_entry\tfunction_name\tload_address\tload_time\tbase_parameter_index\t"
        "field_offset\taddress_pattern\tvalue_size\tvalue_token\tstatus\n"
        "REVENGINSTR.GhidraParameterLoadField/1\t00401000\tFUN_00401000\t00401020\t7\t0\t"
        "0x24\tptrsub\t4\tdef:LOAD@00401020:7:4\tparameter_field_load\n",
        encoding="utf-8",
    )
    pcode_path = tmp_path / "function-pcode-flow.tsv"
    pcode_path.write_text(
        "function_entry\top_address\top_time\topcode\toutput\tinputs\tcallee_entry\tcallee_name\n"
        "00401000\t00401020\t7\tLOAD\tdef:00401020:7:4\tconst:0x1:4\t-\t-\n"
        "00401000\t00401024\t8\tCOPY\tdef:00401024:8:4\tdef:00401020:7:4\t-\t-\n"
        "00401000\t00401030\t9\tRETURN\t-\tdef:00401024:8:4\t-\t-\n",
        encoding="utf-8",
    )
    load_schema_path = ROOT / "schemas" / "ghidra-parameter-load-field-v1.schema.json"
    pcode_schema_path = ROOT / "schemas" / "ghidra-function-pcode-flow-v1.schema.json"
    graph_schema_path = ROOT / "schemas" / "receiver-provenance-graph-v1.schema.json"
    manifest["schemas"].update({
        "parameter_load": {
            "path": str(load_schema_path), "version": "REVENGINSTR.GhidraParameterLoadField/1",
            "sha256": _sha256(load_schema_path),
        },
        "pcode_flow": {
            "path": str(pcode_schema_path), "version": "REVENGINSTR.GhidraFunctionPcodeFlow/1",
            "sha256": _sha256(pcode_schema_path),
        },
        "receiver_graph": {
            "path": str(graph_schema_path), "version": "REVENGINSTR.ReceiverProvenanceGraph/1",
            "sha256": _sha256(graph_schema_path),
        },
    })
    manifest["artifacts"].update({
        "parameter_loads": {
            "path": str(load_path), "role": "input", "kind": "file", "content": "tsv",
            "format": "REVENGINSTR.GhidraParameterLoadField/1", "sha256": _sha256(load_path),
            "schema": "parameter_load",
        },
        "pcode_flow": {
            "path": str(pcode_path), "role": "input", "kind": "file", "content": "tsv",
            "sha256": _sha256(pcode_path),
            "schema": "pcode_flow",
        },
        "load_return_graphs": {
            "path": "load-return-graphs.jsonl", "role": "output", "kind": "file",
            "content": "jsonl", "format": "REVENGINSTR.ReceiverProvenanceGraph/1",
            "schema": "receiver_graph",
        },
    })
    manifest["stages"].append({
        "id": "load_return_flow", "tool": "receiver-load-return-flow",
        "args": [
            "${artifact:parameter_loads}", "${artifact:pcode_flow}",
            "--program-id", "analysis:sample", "--output", "${artifact:load_return_graphs}",
        ],
        "inputs": ["parameter_loads", "pcode_flow"], "outputs": ["load_return_graphs"],
    })
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    summary, code = run_benchmark(manifest_path, mode="smoke", output_path=tmp_path / "summary.json")

    assert code == 0
    assert summary["status"] == "passed"
    assert summary["stages"][1]["tool"] == "receiver-load-return-flow"
    graph = json.loads((tmp_path / "load-return-graphs.jsonl").read_text(encoding="utf-8"))
    assert graph["edges"][0]["relation"] == "return_flow"


def test_benchmark_runs_function_effect_ir_stage(tmp_path: Path) -> None:
    manifest_path = _write_manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    fixture_paths = {
        "parameter_stores": ROOT / "tests/fixtures/parameter-field/parameter-stores.tsv",
        "parameter_loads": ROOT / "tests/fixtures/parameter-field/parameter-loads.tsv",
        "pcode_flow": ROOT / "tests/fixtures/receiver-flow-pcode.tsv",
    }
    schema_files = {
        "parameter_store": "ghidra-parameter-store-field-v1.schema.json",
        "parameter_load": "ghidra-parameter-load-field-v1.schema.json",
        "pcode_flow": "ghidra-function-pcode-flow-v1.schema.json",
        "function_effect_ir": "function-effect-ir-v1.schema.json",
        "function_effect_ir_v2": "function-effect-ir-v2.schema.json",
        "function_summary": "function-summary-v1.schema.json",
        "function_summary_v2": "function-summary-v2.schema.json",
    }
    for schema_id, filename in schema_files.items():
        schema_path = ROOT / "schemas" / filename
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        manifest["schemas"][schema_id] = {
            "path": str(schema_path),
            "version": schema["title"],
            "sha256": _sha256(schema_path),
        }

    formats = {
        "parameter_stores": "REVENGINSTR.GhidraParameterStoreField/1",
        "parameter_loads": "REVENGINSTR.GhidraParameterLoadField/1",
    }
    schema_ids = {
        "parameter_stores": "parameter_store",
        "parameter_loads": "parameter_load",
        "pcode_flow": "pcode_flow",
    }
    for artifact_id, path in fixture_paths.items():
        artifact = {
            "path": str(path), "role": "input", "kind": "file", "content": "tsv",
            "sha256": _sha256(path), "schema": schema_ids[artifact_id],
        }
        if artifact_id in formats:
            artifact["format"] = formats[artifact_id]
        manifest["artifacts"][artifact_id] = artifact

    manifest["artifacts"]["function_effects"] = {
        "path": "function-effects.jsonl", "role": "output", "kind": "file",
        "content": "jsonl", "format": "REVENGINSTR.FunctionEffectIR/1",
        "schema": "function_effect_ir",
    }
    manifest["artifacts"]["function_summaries"] = {
        "path": "function-summaries.jsonl", "role": "output", "kind": "file",
        "content": "jsonl", "format": "REVENGINSTR.FunctionSummary/1",
        "schema": "function_summary",
    }
    manifest["artifacts"]["function_summaries_v2"] = {
        "path": "function-summaries-v2.jsonl", "role": "output", "kind": "file",
        "content": "jsonl", "format": "REVENGINSTR.FunctionSummary/2",
        "schema": "function_summary_v2",
    }
    manifest["artifacts"]["function_effects_v2"] = {
        "path": "function-effects-v2.jsonl", "role": "output", "kind": "file",
        "content": "jsonl", "format": "REVENGINSTR.FunctionEffectIR/2",
        "schema": "function_effect_ir_v2",
    }
    manifest["stages"].append({
        "id": "function_effect_ir_v2", "tool": "function-effect-ir",
        "args": [
            "--program-id", "analysis:sample",
            "--parameter-stores", "${artifact:parameter_stores}",
            "--parameter-loads", "${artifact:parameter_loads}",
            "--pcode-flow", "${artifact:pcode_flow}",
            "--include-generic-memory-ops",
            "--output", "${artifact:function_effects_v2}",
        ],
        "inputs": list(fixture_paths), "outputs": ["function_effects_v2"],
    })
    manifest["stages"].append({
        "id": "function_effect_ir", "tool": "function-effect-ir",
        "args": [
            "--program-id", "analysis:sample",
            "--parameter-stores", "${artifact:parameter_stores}",
            "--parameter-loads", "${artifact:parameter_loads}",
            "--pcode-flow", "${artifact:pcode_flow}",
            "--output", "${artifact:function_effects}",
        ],
        "inputs": list(fixture_paths), "outputs": ["function_effects"],
    })
    manifest["stages"].append({
        "id": "structured_summary", "tool": "structured-summary",
        "args": ["${artifact:function_effects}", "--output", "${artifact:function_summaries}"],
        "inputs": ["function_effects"], "outputs": ["function_summaries"],
        "depends_on": ["function_effect_ir"],
    })
    manifest["stages"].append({
        "id": "structured_summary_v2", "tool": "structured-summary",
        "args": ["${artifact:function_effects_v2}", "--output", "${artifact:function_summaries_v2}"],
        "inputs": ["function_effects_v2"], "outputs": ["function_summaries_v2"],
        "depends_on": ["function_effect_ir_v2"],
    })
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    summary, code = run_benchmark(
        manifest_path, mode="smoke", output_path=tmp_path / "summary.json"
    )

    assert code == 0
    assert summary["status"] == "passed"
    assert summary["stages"][-1]["tool"] == "structured-summary"
    records = [
        json.loads(line)
        for line in (tmp_path / "function-effects.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    effect_schema = json.loads(
        (ROOT / "schemas/function-effect-ir-v1.schema.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(effect_schema)
    for record in records:
        validator.validate(record)
    assert len(records) == 2
    v2_records = [
        json.loads(line)
        for line in (tmp_path / "function-effects-v2.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    v2_schema = json.loads((ROOT / "schemas/function-effect-ir-v2.schema.json").read_text(encoding="utf-8"))
    for record in v2_records:
        Draft202012Validator(v2_schema).validate(record)
    assert len(v2_records) == 2
    assert any(effect["kind"] == "memory_read" for record in v2_records for effect in record["effects"])
    function_summaries = [
        json.loads(line)
        for line in (tmp_path / "function-summaries.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    summary_schema = json.loads((ROOT / "schemas/function-summary-v1.schema.json").read_text(encoding="utf-8"))
    for record in function_summaries:
        Draft202012Validator(summary_schema).validate(record)
    assert len(function_summaries) == len(records)
    function_summaries_v2 = [
        json.loads(line)
        for line in (tmp_path / "function-summaries-v2.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    summary_schema_v2 = json.loads((ROOT / "schemas/function-summary-v2.schema.json").read_text(encoding="utf-8"))
    for record in function_summaries_v2:
        Draft202012Validator(summary_schema_v2).validate(record)
    assert len(function_summaries_v2) == len(v2_records)
    assert any(claim["kind"] == "memory_read" for record in function_summaries_v2 for claim in record["claims"])


def test_benchmark_runs_semantic_role_evaluation_stage(tmp_path: Path) -> None:
    manifest_path = _write_manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    fixture_dir = ROOT / "tests/fixtures/semantic-role"
    fixture_paths = {
        "role_labels": fixture_dir / "labels.jsonl",
        "role_predictions": fixture_dir / "predictions.jsonl",
        "training_families": fixture_dir / "training-families.jsonl",
    }
    schema_files = {
        "role_labels": "semantic-role-label-v1.schema.json",
        "role_predictions": "semantic-role-prediction-v1.schema.json",
        "training_families": "function-families-v1.schema.json",
        "role_evaluation": "semantic-role-evaluation-v1.schema.json",
    }
    for schema_id, filename in schema_files.items():
        schema_path = ROOT / "schemas" / filename
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        manifest["schemas"][schema_id] = {
            "path": str(schema_path),
            "version": schema["title"],
            "sha256": _sha256(schema_path),
        }

    formats = {
        "role_labels": "REVENGINSTR.SemanticRoleLabel/1",
        "role_predictions": "REVENGINSTR.SemanticRolePrediction/1",
        "training_families": "REVENGINSTR.FunctionFamilies/1",
    }
    for artifact_id, path in fixture_paths.items():
        manifest["artifacts"][artifact_id] = {
            "path": str(path), "role": "input", "kind": "file", "content": "jsonl",
            "format": formats[artifact_id], "sha256": _sha256(path), "schema": artifact_id,
        }
    manifest["artifacts"]["role_evaluation"] = {
        "path": "semantic-role-evaluation.json", "role": "output", "kind": "file",
        "content": "json", "format": "REVENGINSTR.SemanticRoleEvaluation/1",
        "schema": "role_evaluation",
    }
    manifest["stages"].append({
        "id": "semantic_role_evaluation", "tool": "semantic-role-evaluate",
        "args": [
            "${artifact:role_labels}", "${artifact:role_predictions}",
            "--training-families", "${artifact:training_families}",
            "--output", "${artifact:role_evaluation}",
        ],
        "inputs": list(fixture_paths), "outputs": ["role_evaluation"],
    })
    manifest["metrics"].append({
        "name": "role_micro_f1", "artifact": "role_evaluation",
        "json_pointer": "/micro_f1", "minimum": 0.0,
    })
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    summary, code = run_benchmark(
        manifest_path, mode="smoke", output_path=tmp_path / "summary.json"
    )

    assert code == 0
    assert summary["status"] == "passed"
    assert summary["stages"][-1]["tool"] == "semantic-role-evaluate"
    report = json.loads((tmp_path / "semantic-role-evaluation.json").read_text(encoding="utf-8"))
    assert report["family_disjointness"] == "verified"
    assert report["rows"] == 4


def test_benchmark_runs_decision_ledger_audit_stage(tmp_path: Path) -> None:
    manifest_path = _write_manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    fixture = ROOT / "tests/fixtures/decision-ledger/events.jsonl"
    schema_files = {
        "ledger_event": "analysis-decision-ledger-event-v1.schema.json",
        "ledger_audit": "analysis-decision-ledger-audit-v1.schema.json",
    }
    for schema_id, filename in schema_files.items():
        schema_path = ROOT / "schemas" / filename
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        manifest["schemas"][schema_id] = {
            "path": str(schema_path), "version": schema["title"], "sha256": _sha256(schema_path),
        }
    manifest["artifacts"]["ledger_events"] = {
        "path": str(fixture), "role": "input", "kind": "file", "content": "jsonl",
        "format": "REVENGINSTR.AnalysisDecisionLedgerEvent/1",
        "sha256": _sha256(fixture), "schema": "ledger_event",
    }
    manifest["artifacts"]["ledger_audit"] = {
        "path": "ledger-audit.json", "role": "output", "kind": "file", "content": "json",
        "format": "REVENGINSTR.AnalysisDecisionLedgerAudit/1", "schema": "ledger_audit",
    }
    manifest["stages"].append({
        "id": "decision_ledger_audit", "tool": "decision-ledger-audit",
        "args": ["${artifact:ledger_events}", "--output", "${artifact:ledger_audit}"],
        "inputs": ["ledger_events"], "outputs": ["ledger_audit"],
    })
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    summary, code = run_benchmark(manifest_path, mode="smoke", output_path=tmp_path / "summary.json")
    assert code == 0
    assert summary["status"] == "passed"
    assert summary["stages"][-1]["tool"] == "decision-ledger-audit"
    report = json.loads((tmp_path / "ledger-audit.json").read_text(encoding="utf-8"))
    schema = json.loads((ROOT / "schemas/analysis-decision-ledger-audit-v1.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator(schema).validate(report)
    assert report["subjects"] == 6


def test_benchmark_runs_analysis_invalidation_plan_stage(tmp_path: Path) -> None:
    manifest_path = _write_manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    graph = {
        "format": "REVENGINSTR.AnalysisTaskGraph/1",
        "tasks": [
            {
                "task_id": "export_pcode", "task_kind": "pcode_export",
                "configuration_sha256": "a" * 64, "depends_on": [],
                "input_artifacts": ["binary"], "output_artifacts": ["pcode"],
            },
            {
                "task_id": "classify", "task_kind": "classification",
                "configuration_sha256": "b" * 64, "depends_on": ["export_pcode"],
                "input_artifacts": ["pcode"], "output_artifacts": ["predictions"],
            },
        ],
    }
    graph_path = tmp_path / "task-graph.json"
    graph_path.write_text(json.dumps(graph), encoding="utf-8")
    graph_schema_path = ROOT / "schemas" / "analysis-task-graph-v1.schema.json"
    plan_schema_path = ROOT / "schemas" / "analysis-invalidation-plan-v1.schema.json"
    manifest["schemas"].update({
        "task_graph": {
            "path": str(graph_schema_path), "version": "REVENGINSTR.AnalysisTaskGraph/1",
            "sha256": _sha256(graph_schema_path),
        },
        "invalidation_plan": {
            "path": str(plan_schema_path), "version": "REVENGINSTR.AnalysisInvalidationPlan/1",
            "sha256": _sha256(plan_schema_path),
        },
    })
    manifest["artifacts"].update({
        "task_graph": {
            "path": str(graph_path), "role": "input", "kind": "file", "content": "json",
            "format": "REVENGINSTR.AnalysisTaskGraph/1", "sha256": _sha256(graph_path),
            "schema": "task_graph",
        },
        "invalidation_plan": {
            "path": "invalidation-plan.json", "role": "output", "kind": "file", "content": "json",
            "format": "REVENGINSTR.AnalysisInvalidationPlan/1", "schema": "invalidation_plan",
        },
    })
    manifest["stages"].append({
        "id": "analysis_invalidation_plan", "tool": "analysis-invalidation-plan",
        "args": ["${artifact:task_graph}", "--changed-artifact", "binary", "--output", "${artifact:invalidation_plan}"],
        "inputs": ["task_graph"], "outputs": ["invalidation_plan"],
    })
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    summary, code = run_benchmark(manifest_path, mode="smoke", output_path=tmp_path / "summary.json")
    assert code == 0
    assert summary["status"] == "passed"
    assert summary["stages"][-1]["tool"] == "analysis-invalidation-plan"
    report = json.loads((tmp_path / "invalidation-plan.json").read_text(encoding="utf-8"))
    plan_schema = json.loads(plan_schema_path.read_text(encoding="utf-8"))
    Draft202012Validator(plan_schema).validate(report)
    assert [row["task_id"] for row in report["invalidated_tasks"]] == ["export_pcode", "classify"]


def test_benchmark_runs_evidence_request_plan_stage(tmp_path: Path) -> None:
    manifest_path = _write_manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    candidates = {
        "format": "REVENGINSTR.EvidenceRequestCandidates/1",
        "candidates": [{
            "request_id": "request-1", "subject_id": "subject-1", "subject_kind": "function",
            "action_type": "function_slice", "bounds": {"max_items": 30}, "cost_units": 2,
            "expected_uncertainty_reduction": 0.6, "downstream_leverage": 2.0,
            "rationale_codes": ["missing_receiver_provenance"], "approval_status": "approved",
            "approval_sha256": "a" * 64,
        }],
    }
    candidates_path = tmp_path / "evidence-requests.json"
    candidates_path.write_text(json.dumps(candidates), encoding="utf-8")
    candidates_schema_path = ROOT / "schemas" / "evidence-request-candidates-v1.schema.json"
    plan_schema_path = ROOT / "schemas" / "evidence-request-plan-v1.schema.json"
    manifest["schemas"].update({
        "evidence_candidates": {
            "path": str(candidates_schema_path), "version": "REVENGINSTR.EvidenceRequestCandidates/1",
            "sha256": _sha256(candidates_schema_path),
        },
        "evidence_plan": {
            "path": str(plan_schema_path), "version": "REVENGINSTR.EvidenceRequestPlan/1",
            "sha256": _sha256(plan_schema_path),
        },
    })
    manifest["artifacts"].update({
        "evidence_candidates": {
            "path": str(candidates_path), "role": "input", "kind": "file", "content": "json",
            "format": "REVENGINSTR.EvidenceRequestCandidates/1", "sha256": _sha256(candidates_path),
            "schema": "evidence_candidates",
        },
        "evidence_plan": {
            "path": "evidence-plan.json", "role": "output", "kind": "file", "content": "json",
            "format": "REVENGINSTR.EvidenceRequestPlan/1", "schema": "evidence_plan",
        },
    })
    manifest["stages"].append({
        "id": "evidence_request_plan", "tool": "evidence-request-plan",
        "args": [
            "${artifact:evidence_candidates}", "--budget-units", "2", "--output", "${artifact:evidence_plan}"
        ],
        "inputs": ["evidence_candidates"], "outputs": ["evidence_plan"],
    })
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    summary, code = run_benchmark(manifest_path, mode="smoke", output_path=tmp_path / "summary.json")
    assert code == 0
    assert summary["status"] == "passed"
    assert summary["stages"][-1]["tool"] == "evidence-request-plan"
    report = json.loads((tmp_path / "evidence-plan.json").read_text(encoding="utf-8"))
    Draft202012Validator(json.loads(plan_schema_path.read_text(encoding="utf-8"))).validate(report)
    assert report["selected_requests"][0]["request_id"] == "request-1"


def test_benchmark_runs_call_return_flow_stage(tmp_path: Path) -> None:
    manifest_path = _write_manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    pcode_path = tmp_path / "function-pcode-flow.tsv"
    pcode_path.write_text(
        "function_entry\top_address\top_time\topcode\toutput\tinputs\tcallee_entry\tcallee_name\n"
        "00401000\t00401020\t7\tCALL\tdef:00401020:7:4\tconst:0x401100:4\t00401100\tFUN_00401100\n"
        "00401000\t00401024\t8\tCOPY\tdef:00401024:8:4\tdef:00401020:7:4\t-\t-\n"
        "00401000\t00401030\t9\tRETURN\t-\tdef:00401024:8:4\t-\t-\n",
        encoding="utf-8",
    )
    pcode_schema_path = ROOT / "schemas" / "ghidra-function-pcode-flow-v1.schema.json"
    graph_schema_path = ROOT / "schemas" / "receiver-provenance-graph-v1.schema.json"
    manifest["schemas"].update({
        "pcode_flow": {
            "path": str(pcode_schema_path), "version": "REVENGINSTR.GhidraFunctionPcodeFlow/1",
            "sha256": _sha256(pcode_schema_path),
        },
        "receiver_graph": {
            "path": str(graph_schema_path), "version": "REVENGINSTR.ReceiverProvenanceGraph/1",
            "sha256": _sha256(graph_schema_path),
        },
    })
    manifest["artifacts"].update({
        "pcode_flow": {
            "path": str(pcode_path), "role": "input", "kind": "file", "content": "tsv",
            "sha256": _sha256(pcode_path), "schema": "pcode_flow",
        },
        "call_return_graphs": {
            "path": "call-return-graphs.jsonl", "role": "output", "kind": "file",
            "content": "jsonl", "format": "REVENGINSTR.ReceiverProvenanceGraph/1",
            "schema": "receiver_graph",
        },
    })
    manifest["stages"].append({
        "id": "call_return_flow", "tool": "receiver-call-return-flow",
        "args": [
            "${artifact:pcode_flow}", "--program-id", "analysis:sample",
            "--output", "${artifact:call_return_graphs}",
        ],
        "inputs": ["pcode_flow"], "outputs": ["call_return_graphs"],
    })
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    summary, code = run_benchmark(manifest_path, mode="smoke", output_path=tmp_path / "summary.json")

    assert code == 0
    assert summary["status"] == "passed"
    assert summary["stages"][-1]["tool"] == "receiver-call-return-flow"
    graph = json.loads((tmp_path / "call-return-graphs.jsonl").read_text(encoding="utf-8"))
    assert graph["edges"][0]["relation"] == "return_flow"


def test_benchmark_runs_recursive_argument_propagation_stage(tmp_path: Path) -> None:
    manifest_path = _write_manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    argument_path = tmp_path / "argument-roots.tsv"
    argument_path.write_text(
        "format\trow_type\tplan_id\tcallee_entry\tparameter_index\tcaller_entry\t"
        "caller_call_site\tnode_id\tparent_node_id\tdepth\tedge_kind\n"
        "REVENGINSTR.GhidraCallerArgumentSubtree/1\tnode\tplan-inner\t00401000\t0\t"
        "00402000\t00402010\t0\t-1\t0\troot\n"
        "REVENGINSTR.GhidraCallerArgumentSubtree/1\tnode\tplan-outer\t00402000\t0\t"
        "00403000\t00403010\t0\t-1\t0\troot\n",
        encoding="utf-8",
    )
    parameter_root_path = tmp_path / "caller-parameter-roots.tsv"
    parameter_root_path.write_text(
        "format\tplan_id\tcallee_entry\tparameter_index\tcaller_entry\tcaller_call_site\t"
        "caller_parameter_index\targument_node_id\tstatus\n"
        "REVENGINSTR.GhidraCallerArgumentParameterRoot/1\tplan-inner\t00401000\t0\t"
        "00402000\t00402010\t0\t0\tdirect_parameter_root\n"
        "REVENGINSTR.GhidraCallerArgumentParameterRoot/1\tplan-outer\t00402000\t0\t"
        "00403000\t00403010\t1\t0\tdirect_parameter_root\n",
        encoding="utf-8",
    )
    parameter_root_schema = ROOT / "schemas" / "ghidra-caller-argument-parameter-root-v1.schema.json"
    graph_schema = ROOT / "schemas" / "receiver-provenance-graph-v1.schema.json"
    manifest["schemas"].update({
        "parameter_roots": {
            "path": str(parameter_root_schema),
            "version": "REVENGINSTR.GhidraCallerArgumentParameterRoot/1",
            "sha256": _sha256(parameter_root_schema),
        },
        "receiver_graph": {
            "path": str(graph_schema), "version": "REVENGINSTR.ReceiverProvenanceGraph/1",
            "sha256": _sha256(graph_schema),
        },
    })
    manifest["artifacts"].update({
        "argument_roots": {
            "path": str(argument_path), "role": "input", "kind": "file", "content": "tsv",
            "format": "REVENGINSTR.GhidraCallerArgumentSubtree/1", "sha256": _sha256(argument_path),
        },
        "caller_parameter_roots": {
            "path": str(parameter_root_path), "role": "input", "kind": "file", "content": "tsv",
            "format": "REVENGINSTR.GhidraCallerArgumentParameterRoot/1",
            "sha256": _sha256(parameter_root_path), "schema": "parameter_roots",
        },
        "propagated_graph": {
            "path": "propagated.jsonl", "role": "output", "kind": "file",
            "content": "jsonl", "format": "REVENGINSTR.ReceiverProvenanceGraph/1",
            "schema": "receiver_graph",
        },
    })
    manifest["stages"].append({
        "id": "argument_propagation", "tool": "receiver-argument-propagate",
        "args": [
            "${artifact:argument_roots}", "${artifact:caller_parameter_roots}",
            "--target-entry", "00401000", "--target-parameter-index", "0",
            "--program-id", "analysis:sample", "--output", "${artifact:propagated_graph}",
        ],
        "inputs": ["argument_roots", "caller_parameter_roots"],
        "outputs": ["propagated_graph"],
    })
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    summary, code = run_benchmark(manifest_path, mode="smoke", output_path=tmp_path / "summary.json")

    assert code == 0
    assert summary["status"] == "passed"
    assert summary["stages"][1]["tool"] == "receiver-argument-propagate"
    graph = json.loads((tmp_path / "propagated.jsonl").read_text(encoding="utf-8"))
    assert len(graph["edges"]) == 2
    assert {edge["relation"] for edge in graph["edges"]} == {"argument_flow"}


def test_benchmark_runs_selective_threshold_sweep_stage(tmp_path: Path) -> None:
    manifest_path = _write_manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    classifier_manifest_path = tmp_path / "classifier-manifest.json"
    classifier_manifest_path.write_text(json.dumps({
        "format": "REVENGINSTR.SelectiveClassifier/1",
        "classes": ["alpha", "beta"],
        "calibration": {"source": "family_grouped_oof"},
        "functions": 4,
        "families": 4,
        "class_distribution": {"alpha": 2, "beta": 2},
    }), encoding="utf-8")
    predictions_path = tmp_path / "oof-predictions.jsonl"
    predictions_path.write_text(
        "".join(json.dumps({
            "format": "REVENGINSTR.SelectiveClassifier/1",
            "id": record_id,
            "family_id": f"family-{record_id}",
            "truth": truth,
            "prediction": prediction,
            "correct": truth == prediction,
            "confidence": confidence,
        }) + "\n" for record_id, truth, prediction, confidence in [
            ("a0", "alpha", "alpha", 0.95),
            ("a1", "alpha", "alpha", 0.85),
            ("b0", "beta", "beta", 0.90),
            ("b1", "beta", "alpha", 0.60),
        ]),
        encoding="utf-8",
    )
    sweep_schema_path = ROOT / "schemas" / "selective-threshold-sweep-v1.schema.json"
    manifest["schemas"]["threshold_sweep"] = {
        "path": str(sweep_schema_path), "version": "REVENGINSTR.SelectiveThresholdSweep/1",
        "sha256": _sha256(sweep_schema_path),
    }
    manifest["artifacts"].update({
        "classifier_manifest": {
            "path": str(classifier_manifest_path), "role": "input", "kind": "file",
            "content": "json", "sha256": _sha256(classifier_manifest_path),
        },
        "oof_predictions": {
            "path": str(predictions_path), "role": "input", "kind": "file",
            "content": "jsonl", "sha256": _sha256(predictions_path),
        },
        "threshold_sweep": {
            "path": "threshold-sweep.json", "role": "output", "kind": "file",
            "content": "json", "format": "REVENGINSTR.SelectiveThresholdSweep/1",
            "schema": "threshold_sweep",
        },
    })
    manifest["stages"].append({
        "id": "threshold_sweep", "tool": "selective-threshold-sweep",
        "args": [
            "${artifact:classifier_manifest}", "${artifact:oof_predictions}",
            "--output", "${artifact:threshold_sweep}",
            "--target-precision", "0.8", "--min-examples", "1",
        ],
        "inputs": ["classifier_manifest", "oof_predictions"], "outputs": ["threshold_sweep"],
    })
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    summary, code = run_benchmark(manifest_path, mode="smoke", output_path=tmp_path / "summary.json")

    assert code == 0
    assert summary["status"] == "passed"
    assert summary["stages"][-1]["tool"] == "selective-threshold-sweep"
    sweep = json.loads((tmp_path / "threshold-sweep.json").read_text(encoding="utf-8"))
    assert sweep["classes"]["alpha"]["sweeps"][0]["status"] == "feasible"
    assert sweep["source"]["prediction_rows"] == 4


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


def test_benchmark_runs_heldout_classifier_error_buckets(tmp_path: Path) -> None:
    manifest_path = _write_manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    predictions_path = tmp_path / "heldout-predictions.jsonl"
    predictions_path.write_text("".join(json.dumps(row) + "\n" for row in [
        {
            "format": "REVENGINSTR.SelectiveClassifier/1", "id": "e1", "family_id": "family-a",
            "truth": "alpha", "prediction": "beta", "correct": False,
            "action": "accept", "confidence": 0.92,
        },
        {
            "format": "REVENGINSTR.SelectiveClassifier/1", "id": "e2", "family_id": "family-b",
            "truth": "beta", "prediction": "beta", "correct": True,
            "action": "review", "confidence": 0.70,
        },
    ]), encoding="utf-8")
    evaluation_report_path = tmp_path / "threshold-evaluation.json"
    evaluation_report_path.write_text(json.dumps({
        "format": "REVENGINSTR.SelectiveThresholdEvaluation/1",
        "source": {
            "classifier_format": "REVENGINSTR.SelectiveClassifier/1",
            "evaluation_predictions_sha256": _sha256(predictions_path),
            "evaluation_rows": 2, "evaluation_families": 2, "family_disjoint": True,
        },
        "classes": {"alpha": {}, "beta": {}},
    }), encoding="utf-8")
    error_schema = ROOT / "schemas" / "classifier-error-buckets-v1.schema.json"
    manifest["schemas"]["error_buckets"] = {
        "path": str(error_schema), "version": "REVENGINSTR.ClassifierErrorBuckets/1",
        "sha256": _sha256(error_schema),
    }
    manifest["artifacts"].update({
        "evaluation_report": {
            "path": str(evaluation_report_path), "role": "input", "kind": "file",
            "content": "json", "sha256": _sha256(evaluation_report_path),
        },
        "heldout_predictions": {
            "path": str(predictions_path), "role": "input", "kind": "file",
            "content": "jsonl", "sha256": _sha256(predictions_path),
        },
        "error_buckets": {
            "path": "error-buckets.json", "role": "output", "kind": "file",
            "content": "json", "format": "REVENGINSTR.ClassifierErrorBuckets/1",
            "schema": "error_buckets",
        },
    })
    manifest["stages"].append({
        "id": "classifier_error_buckets", "tool": "classifier-error-buckets",
        "args": [
            "${artifact:evaluation_report}", "${artifact:heldout_predictions}",
            "--output", "${artifact:error_buckets}",
        ],
        "inputs": ["evaluation_report", "heldout_predictions"], "outputs": ["error_buckets"],
    })
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    summary, code = run_benchmark(manifest_path, mode="smoke", output_path=tmp_path / "summary.json")

    assert code == 0
    assert summary["status"] == "passed"
    assert summary["stages"][-1]["tool"] == "classifier-error-buckets"
    report = json.loads((tmp_path / "error-buckets.json").read_text(encoding="utf-8"))
    assert report["error_rows"] == 1
    assert report["accepted_error_rows"] == 1


def test_benchmark_runs_family_heldout_threshold_evaluation(tmp_path: Path) -> None:
    manifest_path = _write_manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    classifier_manifest = tmp_path / "classifier.json"
    classifier_manifest.write_text(json.dumps({
        "format": "REVENGINSTR.SelectiveClassifier/1",
        "classes": ["alpha", "beta"],
        "calibration": {"source": "family_grouped_oof"},
        "functions": 2,
        "families": 2,
        "class_distribution": {"alpha": 1, "beta": 1},
    }), encoding="utf-8")
    oof = tmp_path / "oof.jsonl"
    oof.write_text("".join(json.dumps({
        "format": "REVENGINSTR.SelectiveClassifier/1",
        "id": record_id, "family_id": family, "truth": label, "prediction": label,
        "correct": True, "confidence": 0.9,
    }) + "\n" for record_id, family, label in [("a", "train-a", "alpha"), ("b", "train-b", "beta")]), encoding="utf-8")
    evaluation = tmp_path / "evaluation.jsonl"
    evaluation.write_text("".join(json.dumps({
        "format": "REVENGINSTR.SelectiveClassifier/1",
        "id": record_id, "family_id": family, "truth": label, "prediction": label,
        "correct": True, "confidence": confidence,
    }) + "\n" for record_id, family, label, confidence in [
        ("eval-a", "eval-a-family", "alpha", 0.8),
        ("eval-b", "eval-b-family", "beta", 0.95),
    ]), encoding="utf-8")
    evaluation_schema = ROOT / "schemas" / "selective-threshold-evaluation-v1.schema.json"
    manifest["schemas"]["threshold_evaluation"] = {
        "path": str(evaluation_schema),
        "version": "REVENGINSTR.SelectiveThresholdEvaluation/1",
        "sha256": _sha256(evaluation_schema),
    }
    manifest["artifacts"].update({
        "classifier_manifest": {
            "path": str(classifier_manifest), "role": "input", "kind": "file",
            "content": "json", "sha256": _sha256(classifier_manifest),
        },
        "oof_predictions": {
            "path": str(oof), "role": "input", "kind": "file", "content": "jsonl",
            "sha256": _sha256(oof),
        },
        "evaluation_predictions": {
            "path": str(evaluation), "role": "input", "kind": "file", "content": "jsonl",
            "sha256": _sha256(evaluation),
        },
        "threshold_evaluation": {
            "path": "threshold-evaluation.json", "role": "output", "kind": "file",
            "content": "json", "format": "REVENGINSTR.SelectiveThresholdEvaluation/1",
            "schema": "threshold_evaluation",
        },
    })
    manifest["stages"].append({
        "id": "threshold_evaluation", "tool": "selective-threshold-evaluate",
        "args": [
            "${artifact:classifier_manifest}", "${artifact:oof_predictions}",
            "${artifact:evaluation_predictions}", "--output", "${artifact:threshold_evaluation}",
            "--target-precision", "0.8", "--min-train-examples", "1", "--bins", "5",
        ],
        "inputs": ["classifier_manifest", "oof_predictions", "evaluation_predictions"],
        "outputs": ["threshold_evaluation"],
    })
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    summary, code = run_benchmark(manifest_path, mode="smoke", output_path=tmp_path / "summary.json")

    assert code == 0
    assert summary["status"] == "passed"
    assert summary["stages"][-1]["tool"] == "selective-threshold-evaluate"
    report = json.loads((tmp_path / "threshold-evaluation.json").read_text(encoding="utf-8"))
    assert report["source"]["family_disjoint"] is True
    assert report["classes"]["alpha"]["thresholds"][0]["accepted_examples"] == 0


def test_benchmark_runs_selective_subgroup_audit_stage(tmp_path: Path) -> None:
    manifest_path = _write_manifest(tmp_path)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    predictions_path = tmp_path / "subgroup-evaluation.jsonl"
    predictions = [
        {
            "format": "REVENGINSTR.SelectiveClassifier/1", "id": "a", "family_id": "fa",
            "truth": "alpha", "prediction": "alpha", "correct": True,
            "action": "accept", "confidence": 0.9,
        },
        {
            "format": "REVENGINSTR.SelectiveClassifier/1", "id": "b", "family_id": "fb",
            "truth": "beta", "prediction": "alpha", "correct": False,
            "action": "review", "confidence": 0.7,
        },
    ]
    predictions_path.write_text("".join(json.dumps(row) + "\n" for row in predictions), encoding="utf-8")
    subgroups_path = tmp_path / "evaluation-subgroups.jsonl"
    subgroups_path.write_text("".join(json.dumps({
        "format": "REVENGINSTR.EvaluationSubgroup/1", "id": record_id, "subgroup": group,
    }) + "\n" for record_id, group in [("a", "partition-x"), ("b", "partition-y")]), encoding="utf-8")
    evaluation_report_path = tmp_path / "threshold-evaluation.json"
    evaluation_report_path.write_text(json.dumps({
        "format": "REVENGINSTR.SelectiveThresholdEvaluation/1",
        "source": {
            "classifier_format": "REVENGINSTR.SelectiveClassifier/1",
            "evaluation_predictions_sha256": _sha256(predictions_path),
            "evaluation_rows": 2, "evaluation_families": 2, "family_disjoint": True,
        },
        "bin_count": 5,
        "classes": {"alpha": {}, "beta": {}},
    }), encoding="utf-8")
    subgroup_schema = ROOT / "schemas" / "evaluation-subgroup-v1.schema.json"
    audit_schema = ROOT / "schemas" / "selective-subgroup-audit-v1.schema.json"
    manifest["schemas"].update({
        "evaluation_subgroup": {
            "path": str(subgroup_schema), "version": "REVENGINSTR.EvaluationSubgroup/1",
            "sha256": _sha256(subgroup_schema),
        },
        "subgroup_audit": {
            "path": str(audit_schema), "version": "REVENGINSTR.SelectiveSubgroupAudit/1",
            "sha256": _sha256(audit_schema),
        },
    })
    manifest["artifacts"].update({
        "threshold_evaluation": {
            "path": str(evaluation_report_path), "role": "input", "kind": "file",
            "content": "json", "sha256": _sha256(evaluation_report_path),
        },
        "subgroup_predictions": {
            "path": str(predictions_path), "role": "input", "kind": "file",
            "content": "jsonl", "sha256": _sha256(predictions_path),
        },
        "evaluation_subgroups": {
            "path": str(subgroups_path), "role": "input", "kind": "file",
            "content": "jsonl", "sha256": _sha256(subgroups_path), "schema": "evaluation_subgroup",
        },
        "subgroup_audit": {
            "path": "subgroup-audit.json", "role": "output", "kind": "file",
            "content": "json", "format": "REVENGINSTR.SelectiveSubgroupAudit/1",
            "schema": "subgroup_audit",
        },
    })
    manifest["stages"].append({
        "id": "selective_subgroup_audit", "tool": "selective-subgroup-audit",
        "args": [
            "${artifact:threshold_evaluation}", "${artifact:subgroup_predictions}",
            "${artifact:evaluation_subgroups}", "--output", "${artifact:subgroup_audit}",
        ],
        "inputs": ["threshold_evaluation", "subgroup_predictions", "evaluation_subgroups"],
        "outputs": ["subgroup_audit"],
    })
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    summary, code = run_benchmark(manifest_path, mode="smoke", output_path=tmp_path / "summary.json")

    assert code == 0
    assert summary["status"] == "passed"
    assert summary["stages"][-1]["tool"] == "selective-subgroup-audit"
    result = json.loads((tmp_path / "subgroup-audit.json").read_text(encoding="utf-8"))
    assert result["source"]["evaluation_rows"] == 2
    assert result["groups"]["partition-x"]["accuracy"] == 1.0


def test_benchmark_runs_classifier_ablation_audit_stage(tmp_path: Path) -> None:
    manifest_path = _write_manifest(tmp_path)
    benchmark = json.loads(manifest_path.read_text(encoding="utf-8"))
    inputs = {}
    for name, format_name, predictions in [
        ("baseline", "REVENGINSTR.SelectiveClassifier/1", [
            ("a", "alpha", "alpha"), ("b", "beta", "beta"),
        ]),
        ("candidate", "REVENGINSTR.EvidenceSelectiveClassifier/1", [
            ("a", "alpha", "alpha"), ("b", "beta", "alpha"),
        ]),
    ]:
        model_path = tmp_path / f"{name}-model.json"
        model_path.write_text(json.dumps({
                "format": format_name,
                "task": "domain",
            "classes": ["alpha", "beta"],
            "functions": 2,
            "families": 2,
            "dataset_fingerprint_sha256": "a" * 64,
            "calibration": {"source": "family_grouped_oof", "folds": 2, "seed": 5},
        }), encoding="utf-8")
        prediction_path = tmp_path / f"{name}-oof.jsonl"
        prediction_path.write_text("".join(json.dumps({
            "format": format_name, "id": record_id, "family_id": f"family-{record_id}",
            "truth": truth, "prediction": predicted, "correct": truth == predicted,
            "confidence": 0.8, "action": "accept" if truth == predicted else "review",
        }) + "\n" for record_id, truth, predicted in predictions), encoding="utf-8")
        inputs[name] = {
            "manifest_path": model_path.name,
            "manifest_sha256": _sha256(model_path),
            "oof_predictions_path": prediction_path.name,
            "oof_predictions_sha256": _sha256(prediction_path),
        }
        benchmark["artifacts"].update({
            f"{name}_model": {
                "path": str(model_path), "role": "input", "kind": "file",
                "content": "json", "sha256": _sha256(model_path),
            },
            f"{name}_oof": {
                "path": str(prediction_path), "role": "input", "kind": "file",
                "content": "jsonl", "sha256": _sha256(prediction_path),
            },
        })

    ablation_set_path = tmp_path / "ablation-set.json"
    ablation_set = {
        "format": "REVENGINSTR.ClassifierAblationSet/1",
        "baseline": "baseline",
        "variants": inputs,
    }
    ablation_set_path.write_text(json.dumps(ablation_set), encoding="utf-8")
    set_schema = ROOT / "schemas" / "classifier-ablation-set-v1.schema.json"
    report_schema = ROOT / "schemas" / "classifier-ablation-audit-v1.schema.json"
    benchmark["schemas"].update({
        "ablation_set": {
            "path": str(set_schema), "version": "REVENGINSTR.ClassifierAblationSet/1",
            "sha256": _sha256(set_schema),
        },
        "ablation_audit": {
            "path": str(report_schema), "version": "REVENGINSTR.ClassifierAblationAudit/1",
            "sha256": _sha256(report_schema),
        },
    })
    benchmark["artifacts"].update({
        "ablation_set": {
            "path": str(ablation_set_path), "role": "input", "kind": "file",
            "content": "json", "sha256": _sha256(ablation_set_path), "schema": "ablation_set",
        },
        "ablation_audit": {
            "path": "ablation-audit.json", "role": "output", "kind": "file",
            "content": "json", "format": "REVENGINSTR.ClassifierAblationAudit/1",
            "schema": "ablation_audit",
        },
    })
    benchmark["stages"].append({
        "id": "classifier_ablation_audit", "tool": "classifier-ablation-audit",
        "args": ["${artifact:ablation_set}", "--output", "${artifact:ablation_audit}"],
        "inputs": ["ablation_set"],
        "outputs": ["ablation_audit"],
    })
    manifest_path.write_text(json.dumps(benchmark, indent=2) + "\n", encoding="utf-8")

    summary, code = run_benchmark(manifest_path, mode="smoke", output_path=tmp_path / "summary.json")

    assert code == 0
    assert summary["status"] == "passed"
    assert summary["stages"][-1]["tool"] == "classifier-ablation-audit"
    report = json.loads((tmp_path / "ablation-audit.json").read_text(encoding="utf-8"))
    assert report["variants"]["candidate"]["comparison_to_baseline"]["introduced_errors"] == 1

    ablation_set["format"] = "REVENGINSTR.ClassifierAblationSet/2"
    ablation_set["feature_groups"] = ["callgraph", "field", "pcode", "receiver"]
    ablation_set["variants"]["baseline"]["removed_feature_groups"] = []
    ablation_set["variants"]["candidate"]["removed_feature_groups"] = ["receiver"]
    ablation_set_path.write_text(json.dumps(ablation_set), encoding="utf-8")
    set_schema = ROOT / "schemas" / "classifier-ablation-set-v2.schema.json"
    report_schema = ROOT / "schemas" / "classifier-ablation-audit-v2.schema.json"
    benchmark["schemas"]["ablation_set"] = {
        "path": str(set_schema), "version": "REVENGINSTR.ClassifierAblationSet/2",
        "sha256": _sha256(set_schema),
    }
    benchmark["schemas"]["ablation_audit"] = {
        "path": str(report_schema), "version": "REVENGINSTR.ClassifierAblationAudit/2",
        "sha256": _sha256(report_schema),
    }
    benchmark["artifacts"]["ablation_set"]["sha256"] = _sha256(ablation_set_path)
    benchmark["artifacts"]["ablation_audit"]["format"] = "REVENGINSTR.ClassifierAblationAudit/2"
    for artifact in benchmark["artifacts"].values():
        if artifact["role"] != "output":
            continue
        artifact_path = Path(artifact["path"])
        if not artifact_path.is_absolute():
            artifact_path = tmp_path / artifact_path
        if artifact_path.exists():
            artifact_path.unlink()
    manifest_path.write_text(json.dumps(benchmark, indent=2) + "\n", encoding="utf-8")

    summary, code = run_benchmark(manifest_path, mode="smoke", output_path=tmp_path / "summary-v2.json")
    assert code == 0
    assert summary["status"] == "passed"
    report = json.loads((tmp_path / "ablation-audit.json").read_text(encoding="utf-8"))
    assert report["format"] == "REVENGINSTR.ClassifierAblationAudit/2"
    assert report["variants"]["candidate"]["removed_feature_groups"] == ["receiver"]


def test_benchmark_runs_hard_negative_retention_stage(tmp_path: Path) -> None:
    manifest_path = _write_manifest(tmp_path)
    benchmark = json.loads(manifest_path.read_text(encoding="utf-8"))
    predictions_path = tmp_path / "heldout-predictions.jsonl"
    predictions = [
        {
            "format": "REVENGINSTR.SelectiveClassifier/1", "id": "wrong", "family_id": "family-1",
            "truth": "alpha", "prediction": "beta", "correct": False,
            "confidence": 0.96, "action": "accept",
        },
        {
            "format": "REVENGINSTR.SelectiveClassifier/1", "id": "right", "family_id": "family-2",
            "truth": "beta", "prediction": "beta", "correct": True,
            "confidence": 0.98, "action": "accept",
        },
    ]
    predictions_path.write_text("".join(json.dumps(row) + "\n" for row in predictions), encoding="utf-8")
    evaluation_report_path = tmp_path / "threshold-evaluation.json"
    evaluation_report_path.write_text(json.dumps({
        "format": "REVENGINSTR.SelectiveThresholdEvaluation/1",
        "source": {
            "classifier_format": "REVENGINSTR.SelectiveClassifier/1",
            "evaluation_predictions_sha256": _sha256(predictions_path),
            "evaluation_rows": 2, "evaluation_families": 2, "family_disjoint": True,
        },
        "classes": {"alpha": {}, "beta": {}},
    }), encoding="utf-8")
    negative_schema = ROOT / "schemas" / "classifier-hard-negative-set-v1.schema.json"
    benchmark["schemas"]["hard_negatives"] = {
        "path": str(negative_schema), "version": "REVENGINSTR.ClassifierHardNegativeSet/1",
        "sha256": _sha256(negative_schema),
    }
    benchmark["artifacts"].update({
        "evaluation_report": {
            "path": str(evaluation_report_path), "role": "input", "kind": "file",
            "content": "json", "sha256": _sha256(evaluation_report_path),
        },
        "heldout_predictions": {
            "path": str(predictions_path), "role": "input", "kind": "file",
            "content": "jsonl", "sha256": _sha256(predictions_path),
        },
        "hard_negatives": {
            "path": "hard-negatives.json", "role": "output", "kind": "file",
            "content": "json", "format": "REVENGINSTR.ClassifierHardNegativeSet/1",
            "schema": "hard_negatives",
        },
    })
    benchmark["stages"].append({
        "id": "retain_hard_negatives", "tool": "retain-hard-negatives",
        "args": [
            "${artifact:evaluation_report}", "${artifact:heldout_predictions}",
            "--output", "${artifact:hard_negatives}",
        ],
        "inputs": ["evaluation_report", "heldout_predictions"], "outputs": ["hard_negatives"],
    })
    manifest_path.write_text(json.dumps(benchmark, indent=2) + "\n", encoding="utf-8")

    summary, code = run_benchmark(manifest_path, mode="smoke", output_path=tmp_path / "summary.json")

    assert code == 0
    assert summary["status"] == "passed"
    assert summary["stages"][-1]["tool"] == "retain-hard-negatives"
    result = json.loads((tmp_path / "hard-negatives.json").read_text(encoding="utf-8"))
    assert result["selection"]["selected_rows"] == 1
    assert result["examples"][0]["id"] == "wrong"
