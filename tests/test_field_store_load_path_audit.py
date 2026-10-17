from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.benchmark import run_benchmark
from revenginstr.receiver.field_flow import audit_field_store_load_paths, main
from revenginstr.receiver.provenance import (
    PARAMETER_LOAD_FORMAT,
    PARAMETER_STORE_FORMAT,
    build_field_access_pair_graphs,
)


ROOT = Path(__file__).resolve().parents[1]
CFG_FIXTURE = ROOT / "tests/fixtures/function-pcode-cfg/synthetic.jsonl"
CFG_SCHEMA = json.loads((ROOT / "schemas/ghidra-function-pcode-cfg-v1.schema.json").read_text(encoding="utf-8"))
AUDIT_SCHEMA = json.loads((ROOT / "schemas/field-store-load-path-audit-v1.schema.json").read_text(encoding="utf-8"))


def _pair_graphs(
    *, load_time: int | None = 11, field_offset: str = "0x10", source_parameter_index: int = 1
):
    store_rows = [{
        "format": PARAMETER_STORE_FORMAT,
        "function_entry": "00401000",
        "function_name": "sub_00401000",
        "store_address": "00401020",
        "store_time": "7",
        "destination_parameter_index": "0",
        "destination_offset": field_offset,
        "destination_pattern": "ptrsub",
        "source_parameter_index": str(source_parameter_index),
        "value_size": "4",
        "status": "parameter_to_parameter_field",
    }]
    load_rows = [{
        "format": PARAMETER_LOAD_FORMAT,
        "function_entry": "00401000",
        "function_name": "sub_00401000",
        "load_address": "00401030",
        "load_time": "-" if load_time is None else str(load_time),
        "base_parameter_index": "0",
        "field_offset": field_offset,
        "address_pattern": "ptrsub",
        "value_size": "4",
        "value_token": "def:LOAD@00401030:11:4",
        "status": "parameter_field_load",
    }]
    return build_field_access_pair_graphs(store_rows, load_rows, program_id="synthetic:cfg")


def _cfg_rows():
    return [json.loads(CFG_FIXTURE.read_text(encoding="utf-8"))]


def test_cfg_fixture_and_candidate_path_preserve_both_input_provenances() -> None:
    cfg_row = _cfg_rows()[0]
    Draft202012Validator.check_schema(CFG_SCHEMA)
    Draft202012Validator(CFG_SCHEMA).validate(cfg_row)
    rows = audit_field_store_load_paths(
        _pair_graphs(), [cfg_row], pair_graph_sha256="a" * 64, cfg_sha256="b" * 64,
    )
    assert len(rows) == 1
    row = rows[0]
    Draft202012Validator.check_schema(AUDIT_SCHEMA)
    Draft202012Validator(AUDIT_SCHEMA).validate(row)
    assert row["status"] == "candidate_path_compatible"
    assert row["path_block_indices"] == [0, 2, 3]
    assert row["provenance"]["pair_graph_sha256"] == "a" * 64
    assert row["provenance"]["cfg_sha256"] == "b" * 64
    assert row["provenance"]["path_expansion_cap"] == 1_000_000
    assert row["provenance"]["path_expansions_used"] > 0
    assert "value_flow" not in json.dumps(row)


def test_cfg_audit_distinguishes_blocked_missing_path_and_unlocated_events() -> None:
    cfg = _cfg_rows()
    blocked = json.loads(json.dumps(cfg))
    blocked[0]["blocks"][2]["operations"][0]["opcode"] = "CALLIND"
    row = audit_field_store_load_paths(
        _pair_graphs(), blocked, pair_graph_sha256="a" * 64, cfg_sha256="b" * 64,
    )[0]
    assert row["status"] == "intervening_store_or_call"
    assert row["path_block_indices"][0] == 0
    assert row["path_block_indices"][-1] == 3

    disconnected = json.loads(json.dumps(cfg))
    disconnected[0]["blocks"][0]["successors"] = []
    row = audit_field_store_load_paths(
        _pair_graphs(), disconnected, pair_graph_sha256="a" * 64, cfg_sha256="b" * 64,
    )[0]
    assert row["status"] == "no_cfg_path"

    row = audit_field_store_load_paths(
        _pair_graphs(load_time=12), cfg, pair_graph_sha256="a" * 64, cfg_sha256="b" * 64,
    )[0]
    assert row["status"] == "event_not_located"


def test_cfg_audit_keeps_offset_signs_and_rejects_bad_joins_or_budgets() -> None:
    [row] = audit_field_store_load_paths(
        _pair_graphs(field_offset="-0x4"), _cfg_rows(),
        pair_graph_sha256="a" * 64, cfg_sha256="b" * 64,
    )
    assert row["field_offset"] == "-0x4"

    with pytest.raises(ValueError, match="missing CFG"):
        audit_field_store_load_paths(
            _pair_graphs(), [], pair_graph_sha256="a" * 64, cfg_sha256="b" * 64,
        )
    other_program_cfg = _cfg_rows()
    other_program_cfg[0]["program_id"] = "synthetic:other"
    with pytest.raises(ValueError, match="missing CFG for program"):
        audit_field_store_load_paths(
            _pair_graphs(), other_program_cfg,
            pair_graph_sha256="a" * 64, cfg_sha256="b" * 64,
        )
    with pytest.raises(ValueError, match="max_pairs must be positive"):
        audit_field_store_load_paths(
            _pair_graphs(), _cfg_rows(), pair_graph_sha256="a" * 64,
            cfg_sha256="b" * 64, max_pairs=0,
        )
    with pytest.raises(ValueError, match="budget exceeded"):
        audit_field_store_load_paths(
            [*_pair_graphs(), *_pair_graphs(source_parameter_index=2)], _cfg_rows(),
            pair_graph_sha256="a" * 64, cfg_sha256="b" * 64, max_pairs=1,
        )
    with pytest.raises(ValueError, match="CFG path search budget exceeded"):
        audit_field_store_load_paths(
            _pair_graphs(), _cfg_rows(), pair_graph_sha256="a" * 64,
            cfg_sha256="b" * 64, max_path_expansions=1,
        )


def test_cfg_audit_cli_and_benchmark_stage(tmp_path: Path) -> None:
    pair_path = tmp_path / "pairs.jsonl"
    pair_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in _pair_graphs()), encoding="utf-8")
    output = tmp_path / "nested" / "audit.jsonl"
    assert main([str(pair_path), str(CFG_FIXTURE), "--output", str(output)]) == 0
    [row] = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert row["status"] == "candidate_path_compatible"
    assert row["provenance"]["pair_graph_sha256"] == sha256(pair_path.read_bytes()).hexdigest()

    pair_schema_path = ROOT / "schemas/receiver-provenance-graph-v1.schema.json"
    cfg_schema_path = ROOT / "schemas/ghidra-function-pcode-cfg-v1.schema.json"
    output_schema_path = ROOT / "schemas/field-store-load-path-audit-v1.schema.json"
    schemas = {
        name: {"path": str(path), "version": json.loads(path.read_text())["title"],
              "sha256": sha256(path.read_bytes()).hexdigest()}
        for name, path in (
            ("pair_graph", pair_schema_path), ("pcode_cfg", cfg_schema_path), ("path_audit", output_schema_path),
        )
    }
    artifacts = {
        "pair_graphs": {"path": str(pair_path), "role": "input", "kind": "file", "content": "jsonl",
                        "format": "REVENGINSTR.ReceiverProvenanceGraph/1", "sha256": sha256(pair_path.read_bytes()).hexdigest(), "schema": "pair_graph"},
        "pcode_cfg": {"path": str(CFG_FIXTURE), "role": "input", "kind": "file", "content": "jsonl",
                       "format": "REVENGINSTR.GhidraFunctionPcodeCFG/1", "sha256": sha256(CFG_FIXTURE.read_bytes()).hexdigest(), "schema": "pcode_cfg"},
        "path_audit": {"path": "path-audit.jsonl", "role": "output", "kind": "file", "content": "jsonl",
                       "format": "REVENGINSTR.FieldStoreLoadPathAudit/1", "schema": "path_audit"},
    }
    manifest = {
        "format": "REVENGINSTR.BenchmarkManifest/1",
        "benchmark": {
            "id": "synthetic-field-flow", "dataset_id": "synthetic-field-flow",
            "dataset_artifact": "pair_graphs", "split_id": "synthetic",
            "family_set_id": None,
        },
        "toolchain": {"revenginstr_version": "0.5.2", "source_revision": "test"},
        "schemas": schemas,
        "artifacts": artifacts,
        "configs": {},
        "stages": [{
        "id": "field_store_load_audit", "tool": "receiver-field-store-load-audit",
        "args": ["${artifact:pair_graphs}", "${artifact:pcode_cfg}", "--output", "${artifact:path_audit}"],
        "inputs": ["pair_graphs", "pcode_cfg"], "outputs": ["path_audit"],
        }],
    }
    tmp_manifest = tmp_path / "manifest.json"
    tmp_manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    summary, code = run_benchmark(tmp_manifest, mode="smoke", output_path=tmp_path / "summary.json")
    assert code == 0
    assert summary["stages"][0]["tool"] == "receiver-field-store-load-audit"
