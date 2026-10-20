from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.effect_ir import build_function_effect_ir, main


ROOT = Path(__file__).resolve().parents[1]
STORE_FIXTURE = ROOT / "tests/fixtures/parameter-field/parameter-stores.tsv"
LOAD_FIXTURE = ROOT / "tests/fixtures/parameter-field/parameter-loads.tsv"
PCODE_FIXTURE = ROOT / "tests/fixtures/receiver-flow-pcode.tsv"
SCHEMA = json.loads((ROOT / "schemas/function-effect-ir-v1.schema.json").read_text(encoding="utf-8"))
SCHEMA_V2 = json.loads((ROOT / "schemas/function-effect-ir-v2.schema.json").read_text(encoding="utf-8"))


def test_function_effect_ir_projects_only_evidence_backed_operations() -> None:
    records = build_function_effect_ir(
        "sample:analysis",
        parameter_store_tsv=STORE_FIXTURE,
        parameter_load_tsv=LOAD_FIXTURE,
        pcode_flow_tsv=PCODE_FIXTURE,
    )
    Draft202012Validator.check_schema(SCHEMA)
    validator = Draft202012Validator(SCHEMA)
    for record in records:
        validator.validate(record)

    assert [record["function_entry"] for record in records] == ["00401000", "00402000"]
    by_function = {record["function_entry"]: record["effects"] for record in records}
    assert {effect["kind"] for effect in by_function["00401000"]} == {
        "parameter_field_read", "parameter_field_write", "return_op"
    }
    assert {effect["kind"] for effect in by_function["00402000"]} == {"direct_call", "return_op"}

    reads = [effect for effect in by_function["00401000"] if effect["kind"] == "parameter_field_read"]
    assert reads[0]["evidence_class"] == "derived_structural"
    assert reads[0]["field_offset"] == "0x10"
    assert reads[0]["provenance"]["artifact_sha256"] == sha256(LOAD_FIXTURE.read_bytes()).hexdigest()
    assert all(effect["provenance"]["record_index"] >= 1 for record in records for effect in record["effects"])

    calls = [effect for effect in by_function["00402000"] if effect["kind"] == "direct_call"]
    assert calls[0]["target_entry"] == "00402100"
    assert calls[0]["evidence_class"] == "exact_static"
    assert build_function_effect_ir(
        "sample:analysis", parameter_store_tsv=STORE_FIXTURE,
        parameter_load_tsv=LOAD_FIXTURE, pcode_flow_tsv=PCODE_FIXTURE,
    ) == records


def test_function_effect_ir_keeps_unresolved_indirect_call_target(tmp_path: Path) -> None:
    source = tmp_path / "pcode.tsv"
    source.write_text(
        "function_entry\top_address\top_time\topcode\toutput\tinputs\tcallee_entry\tcallee_name\n"
        "00401000\t00401020\t7\tCALLIND\tdef:00401020:7:4\tregister:0010:4\t-\t-\n",
        encoding="utf-8",
    )

    [record] = build_function_effect_ir("p", pcode_flow_tsv=source)
    Draft202012Validator(SCHEMA).validate(record)
    [effect] = record["effects"]
    assert effect["kind"] == "indirect_call"
    assert effect["target_entry"] == effect["target_name"] == "-"


def test_function_effect_ir_v2_includes_exact_generic_memory_operations(tmp_path: Path) -> None:
    source = tmp_path / "pcode.tsv"
    source.write_text(
        "function_entry\top_address\top_time\topcode\toutput\tinputs\tcallee_entry\tcallee_name\n"
        "00401000\t00401020\t7\tLOAD\tdef:00401020:7:4\tconst:0x1:4;register:0010:4\t-\t-\n"
        "00401000\t00401024\t8\tSTORE\t-\tconst:0x1:4;register:0010:4;register:0020:4\t-\t-\n"
        "00401000\t00401030\t9\tCALL\t-\tconst:0x402100:4\t00402100\tFUN_00402100\n",
        encoding="utf-8",
    )

    [legacy] = build_function_effect_ir("p", pcode_flow_tsv=source)
    assert legacy["format"] == "REVENGINSTR.FunctionEffectIR/1"
    assert {effect["kind"] for effect in legacy["effects"]} == {"direct_call"}

    [record] = build_function_effect_ir(
        "p", pcode_flow_tsv=source, include_generic_memory_ops=True,
    )
    Draft202012Validator.check_schema(SCHEMA_V2)
    Draft202012Validator(SCHEMA_V2).validate(record)
    effects = {effect["kind"]: effect for effect in record["effects"]}
    assert record["format"] == "REVENGINSTR.FunctionEffectIR/2"
    assert set(effects) == {"memory_read", "memory_write", "direct_call"}
    assert effects["memory_read"]["opcode"] == "LOAD"
    assert effects["memory_read"]["value_token"] == "def:00401020:7:4"
    assert effects["memory_read"]["inputs"] == ["const:0x1:4", "register:0010:4"]
    assert effects["memory_read"]["evidence_class"] == "exact_static"
    assert effects["memory_write"]["opcode"] == "STORE"
    assert effects["memory_write"]["inputs"][-1] == "register:0020:4"
    assert effects["memory_write"]["parameter_index"] is None
    assert all(effect["provenance"]["artifact_sha256"] == sha256(source.read_bytes()).hexdigest() for effect in effects.values())

    with pytest.raises(ValueError, match="require P-code flow"):
        build_function_effect_ir("p", parameter_store_tsv=STORE_FIXTURE, include_generic_memory_ops=True)


def test_function_effect_ir_projects_parameter_rooted_memory_store_accesses(tmp_path: Path) -> None:
    source = tmp_path / "memory-stores.jsonl"
    common = {
        "format": "REVENGINSTR.GhidraMemoryStoreAccess/1",
        "program_id": "sample:analysis",
        "function_entry": "00401000",
        "address": "00401024",
        "time": 8,
        "opcode": "STORE",
        "memory_space": "ram",
        "memory_physical_space": "ram",
        "memory_width_bytes": 4,
        "memory_pointer_width_bytes": 4,
        "memory_space_size_bits": 32,
        "memory_addressable_unit_bytes": 1,
        "pointer_token": "def:00401024:8:4",
        "root_parameter_index": None,
        "offset_bytes": None,
        "location_status": "unresolved",
        "destination_pattern": "unresolved",
        "address_expression_ops": [{
            "address": "00401024", "time": 8, "opcode": "PTRADD",
        }],
    }
    rooted = {
        **common,
        "address": "00401028",
        "time": 12,
        "pointer_token": "def:00401028:12:4",
        "root_parameter_index": 0,
        "offset_bytes": 316,
        "location_status": "parameter_rooted_constant_offset",
        "destination_pattern": "ptradd",
        "address_expression_ops": [{
            "address": "00401028", "time": 12, "opcode": "PTRADD",
        }],
    }
    source.write_text(
        "\n".join(json.dumps(row) for row in (common, rooted)) + "\n",
        encoding="utf-8",
    )

    [record] = build_function_effect_ir(
        "sample:analysis", memory_store_access_jsonl=source,
    )
    Draft202012Validator(SCHEMA).validate(record)
    [effect] = record["effects"]
    assert record["format"] == "REVENGINSTR.FunctionEffectIR/1"
    assert effect["kind"] == "parameter_field_write"
    assert effect["parameter_index"] == 0
    assert effect["field_offset"] == "0x13c"
    assert effect["value_size"] == 4
    assert effect["source_parameter_index"] is None
    assert effect["provenance"] == {
        "source_format": "REVENGINSTR.GhidraMemoryStoreAccess/1",
        "artifact_sha256": sha256(source.read_bytes()).hexdigest(),
        "record_index": 2,
    }
    output = tmp_path / "effects.jsonl"
    assert main([
        "--program-id", "sample:analysis",
        "--memory-store-access", str(source),
        "--output", str(output),
    ]) == 0
    assert json.loads(output.read_text(encoding="utf-8")) == record

    with pytest.raises(ValueError, match="program_id does not match"):
        build_function_effect_ir("another-program", memory_store_access_jsonl=source)

    for field in (
        "memory_space", "memory_width_bytes", "memory_pointer_width_bytes",
        "memory_space_size_bits", "memory_addressable_unit_bytes",
    ):
        malformed_root = {**rooted, field: None}
        source.write_text(json.dumps(malformed_root) + "\n", encoding="utf-8")
        with pytest.raises(ValueError, match=f"invalid {field}"):
            build_function_effect_ir("sample:analysis", memory_store_access_jsonl=source)


def test_function_effect_ir_fails_closed_on_bad_inputs_and_budget(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="at least one input"):
        build_function_effect_ir("p")
    with pytest.raises(ValueError, match="max_effects must be positive"):
        build_function_effect_ir("p", parameter_store_tsv=STORE_FIXTURE, max_effects=0)
    with pytest.raises(ValueError, match="effect budget exceeded"):
        build_function_effect_ir("p", parameter_store_tsv=STORE_FIXTURE, max_effects=1)

    bad = tmp_path / "bad.tsv"
    bad.write_text("format\tfunction_entry\nunknown\t00401000\n", encoding="utf-8")
    with pytest.raises(ValueError, match="unexpected TSV header"):
        build_function_effect_ir("p", parameter_store_tsv=bad)


def test_function_effect_ir_cli_writes_jsonl(tmp_path: Path, capsys) -> None:
    output = tmp_path / "nested" / "effects.jsonl"
    assert main([
        "--program-id", "sample:analysis",
        "--parameter-loads", str(LOAD_FIXTURE),
        "--output", str(output),
    ]) == 0
    [record] = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    Draft202012Validator(SCHEMA).validate(record)
    assert "effects: 2" in capsys.readouterr().out
