from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.effect_ir import build_function_effect_ir
from revenginstr.structured_summary import build_function_summaries, main


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schemas/function-summary-v1.schema.json").read_text(encoding="utf-8"))


def _effect_records():
    return build_function_effect_ir(
        "synthetic:analysis",
        parameter_store_tsv=ROOT / "tests/fixtures/parameter-field/parameter-stores.tsv",
        parameter_load_tsv=ROOT / "tests/fixtures/parameter-field/parameter-loads.tsv",
        pcode_flow_tsv=ROOT / "tests/fixtures/receiver-flow-pcode.tsv",
    )


def test_structured_summary_groups_facts_and_preserves_provenance() -> None:
    records = _effect_records()
    serialized = "".join(json.dumps(record, sort_keys=True) + "\n" for record in records).encode()
    summaries = build_function_summaries(records, source_sha256=hashlib.sha256(serialized).hexdigest())
    Draft202012Validator.check_schema(SCHEMA)
    validator = Draft202012Validator(SCHEMA)
    for summary in summaries:
        validator.validate(summary)

    assert [summary["function_entry"] for summary in summaries] == ["00401000", "00402000"]
    claims = {claim["kind"]: claim for claim in summaries[0]["claims"]}
    assert claims["parameter_field_read"]["attributes"] == {
        "parameter_index": 0, "field_offset": "0x10", "value_size": 4,
    }
    read_support = claims["parameter_field_read"]["support"][0]
    assert read_support["effect_id"]
    assert read_support["provenance"]["source_format"] == "REVENGINSTR.GhidraParameterLoadField/1"
    assert "roles" not in summaries[0]


def test_structured_summary_coalesces_equal_effects_and_keeps_all_support() -> None:
    record = next(row for row in _effect_records() if row["function_entry"] == "00401000")
    read = next(effect for effect in record["effects"] if effect["kind"] == "parameter_field_read")
    duplicate = json.loads(json.dumps(read))
    duplicate["provenance"]["record_index"] += 10
    duplicate["effect_id"] = hashlib.sha256(
        f"{duplicate['provenance']['source_format']}\0{duplicate['provenance']['artifact_sha256']}\0{duplicate['provenance']['record_index']}".encode()
    ).hexdigest()
    record["effects"].append(duplicate)

    summary = build_function_summaries([record], source_sha256="a" * 64)[0]
    read_claim = next(
        claim for claim in summary["claims"]
        if claim["kind"] == "parameter_field_read"
        and claim["attributes"]["parameter_index"] == read["parameter_index"]
        and claim["attributes"]["field_offset"] == read["field_offset"]
    )
    assert len(read_claim["support"]) == 2


def test_structured_summary_rejects_bad_effects_and_duplicate_functions() -> None:
    record = _effect_records()[0]
    bad = json.loads(json.dumps(record))
    bad["effects"][0]["evidence_class"] = "model_prediction"
    with pytest.raises(ValueError, match="unsupported kind, opcode, or evidence class"):
        build_function_summaries([bad], source_sha256="a" * 64)
    with pytest.raises(ValueError, match="duplicate function identity"):
        build_function_summaries([record, record], source_sha256="a" * 64)


def test_structured_summary_cli_writes_hash_pinned_jsonl(tmp_path: Path, capsys) -> None:
    records = _effect_records()
    source = tmp_path / "effects.jsonl"
    source.write_text("".join(json.dumps(record, sort_keys=True) + "\n" for record in records), encoding="utf-8")
    output = tmp_path / "nested" / "summaries.jsonl"
    assert main([str(source), "--output", str(output)]) == 0
    summaries = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    assert all(item["source_effect_ir_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest() for item in summaries)
    assert "claims:" in capsys.readouterr().out
