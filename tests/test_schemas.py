from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

from revenginstr.evidence.aggregate import aggregate
from revenginstr.receiver.infer import infer, read_tsv

ROOT = Path(__file__).resolve().parents[1]


def validator(name: str) -> Draft202012Validator:
    schema = json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def test_pcode_and_callgraph_contract_schemas() -> None:
    pcode = validator("pcode-corpus-v1.schema.json")
    pcode.validate({
        "format": "REVENGINSTR.PcodeCorpus/1",
        "program": "sample.exe",
        "source_entry": "00401000",
        "source_name": "FUN_00401000",
        "external": False,
        "decompile_status": "ok",
        "metrics": {"emitted_ops": 2, "truncated": False},
        "model_text": "ARCH=X8632\nPTR_SIZE=4\n",
    })

    callgraph = validator("callgraph-metrics-v1.schema.json")
    callgraph.validate({
        "format": "REVENGINSTR.CallGraphMetrics/1",
        "id": "fn-1",
        "source_entry": "00401000",
        "metrics": {"fan_in": 2, "resolved_call_ratio_proxy": 0.5, "corpus_call_count": None},
    })
    with pytest.raises(ValidationError):
        callgraph.validate({
            "format": "REVENGINSTR.CallGraphMetrics/1",
            "id": "fn-1",
            "source_entry": "00401000",
            "metrics": {"fan_in": "two"},
        })


def test_evidence_schema_accepts_aggregated_rows_and_rejects_text_features(tmp_path: Path) -> None:
    trace = tmp_path / "trace.jsonl"
    metrics = tmp_path / "callgraph.jsonl"
    write_jsonl(trace, [{"id": "fn-1", "program": "sample.exe", "source_entry": "00401000"}])
    write_jsonl(metrics, [{
        "format": "REVENGINSTR.CallGraphMetrics/1",
        "id": "fn-1",
        "source_entry": "00401000",
        "metrics": {"fan_in": 2, "resolved_call_ratio_proxy": 0.5},
    }])
    rows, _ = aggregate(trace, [metrics], None, None)

    evidence = validator("evidence-v1.schema.json")
    evidence.validate(rows[0])
    evidence.validate({**rows[0], "consumer_metadata": {"program": "sample.exe"}})
    with pytest.raises(ValidationError):
        evidence.validate({**rows[0], "features": {"receiver.class_name": "SecretClass"}})


def test_receiver_inference_schema_keeps_identity_evidence_non_routing() -> None:
    rows = infer([{
        "format": "REVENGINSTR.GhidraIndirectReceiverType/1",
        "source_id": "sample.exe:00401000",
        "call_index": "0",
        "call_address": "00401020",
        "receiver_pointer_depth": "1",
        "pointee_type_name": "Widget",
        "pointee_type_display": "Widget",
        "receiver_type_name": "Widget *",
        "receiver_type_display": "Widget *",
        "receiver_storage_kind": "register",
        "flow_type_node_count": "0",
        "flow_single_pointer_pointee_names_json": "[]",
        "flow_single_pointer_pointee_displays_json": "[]",
    }], [{"class_name": "Widget", "receiver_vtable_id": "sample.exe:00900000"}])

    schema = validator("receiver-inference-v1.schema.json")
    schema.validate(rows[0])
    with pytest.raises(ValidationError):
        schema.validate({**rows[0], "affects_routing": True})


def test_generic_receiver_tsv_row_schema(tmp_path: Path) -> None:
    path = tmp_path / "receiver-types.tsv"
    fields = [
        "format", "source_id", "function_entry", "call_index", "call_address",
        "call_time", "arg_count", "receiver_present", "receiver_storage_kind",
        "receiver_token", "receiver_type_name", "receiver_type_display",
        "receiver_pointer_depth", "pointee_type_name", "pointee_type_display",
        "flow_type_node_count", "flow_single_pointer_pointee_names_json",
        "flow_single_pointer_pointee_displays_json",
    ]
    values = [
        "REVENGINSTR.GhidraIndirectReceiverType/1", "sample.exe:00401000",
        "00401000", "0", "00401020", "4", "2", "1", "register",
        "register:0010:4", "Widget *", "Widget *", "1", "Widget", "Widget",
        "0", "[]", "[]",
    ]
    path.write_text("\t".join(fields) + "\n" + "\t".join(values) + "\n", encoding="utf-8")

    schema = validator("ghidra-indirect-receiver-type-v1.schema.json")
    schema.validate(read_tsv(path)[0])
    with pytest.raises(ValidationError):
        schema.validate({**dict(zip(fields, values)), "format": "consumer.receiver/2"})


def test_generic_function_pcode_flow_tsv_row_schema() -> None:
    schema = validator("ghidra-function-pcode-flow-v1.schema.json")
    schema.validate({
        "function_entry": "00401000",
        "op_address": "00401004",
        "op_time": "7",
        "opcode": "CALL",
        "output": "-",
        "inputs": "const:0x401020:4;register:0010:4",
        "callee_entry": "00401020",
        "callee_name": "FUN_00401020",
    })
    with pytest.raises(ValidationError):
        schema.validate({
            "function_entry": "00401000",
            "op_address": "00401004",
            "op_time": "not-a-sequence-number",
            "opcode": "CALL",
            "output": "-",
            "inputs": "-",
            "callee_entry": "-",
            "callee_name": "-",
        })


def test_generic_defined_string_tsv_row_schema() -> None:
    schema = validator("ghidra-pcode-defined-strings-v1.schema.json")
    schema.validate({
        "format": "REVENGINSTR.GhidraPcodeDefinedString/1",
        "constant_address": "0x401000",
        "data_address": "00401000",
        "byte_offset": "0x0",
        "utf8_base64": "cGF0aC5qc29u",
        "length": "9",
    })
    with pytest.raises(ValidationError):
        schema.validate({
            "format": "NEVERGONE.GhidraPcodeDefinedString/1",
            "constant_address": "0x401000",
            "data_address": "00401000",
            "byte_offset": "0x0",
            "utf8_base64": "cGF0aC5qc29u",
            "length": "9",
        })


def test_generic_address_reference_owner_tsv_row_schema() -> None:
    schema = validator("ghidra-address-reference-owners-v1.schema.json")
    schema.validate({
        "format": "REVENGINSTR.GhidraAddressReferenceOwner/1",
        "target_address": "00401000",
        "target_block": ".data",
        "target_symbol": "-",
        "reference_from": "00402010",
        "reference_type": "DATA",
        "reference_source": "ANALYSIS",
        "operand_index": "-",
        "from_symbol": "-",
        "from_instruction": "-",
        "containing_function_entry": "-",
        "containing_function_name": "-",
    })


def test_validation_manifest_and_drift_schemas() -> None:
    digest = "a" * 64
    frozen = validator("frozen-validation-v1.schema.json")
    frozen.validate({
        "format": "REVENGINSTR.FrozenValidation/1",
        "tag": "holdout-v1",
        "selection": "stable_hash_identity_disjoint",
        "selection_salt": "revenginstr-frozen-v1",
        "limit": 500,
        "record_id_fallback": "program:source_entry",
        "include_external": False,
        "source_corpus": {
            "path": "wide.jsonl",
            "sha256": digest,
            "input_rows": 1000,
            "eligible": 700,
            "eligibility_removed": 200,
            "excluded_overlap": 100,
        },
        "eligibility_traces": [{"path": "eligible.jsonl", "sha256": digest}],
        "exclusion_traces": [{"path": "train.jsonl", "sha256": digest}],
        "frozen_corpus": {"path": "corpus.jsonl", "sha256": digest, "rows": 500},
        "trace": {"path": "trace.jsonl", "sha256": digest, "rows": 500},
    })

    drift = validator("drift-audit-v1.schema.json")
    shift = {
        "reference": {"engine": 0.5, "game": 0.5},
        "frozen": {"engine": 0.6, "game": 0.4},
        "js_divergence_bits": 0.01,
    }
    drift.validate({
        "format": "REVENGINSTR.DriftAudit/1",
        "labels_available": False,
        "reference_rows": 100,
        "frozen_rows": 50,
        "categorical_shift": {
            "prediction": shift,
            "base_action": shift,
            "routed_action": shift,
        },
        "router_intervention": {},
        "numeric_shift_all": {},
        "numeric_shift_base_accept": {},
        "evidence_shift": {
            "reference_rows": 100,
            "frozen_rows": 50,
            "core": {},
            "top_feature_coverage_shifts": [],
        },
        "severity": {
            "level": "low",
            "diagnostic_only": True,
            "thresholds": {},
            "observed": {},
        },
        "note": "diagnostic only",
    })
