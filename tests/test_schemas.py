from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError

from revenginstr.evidence.aggregate import aggregate

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
