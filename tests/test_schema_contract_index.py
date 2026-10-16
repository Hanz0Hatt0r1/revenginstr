from __future__ import annotations

import json
from pathlib import Path

from jsonschema import Draft202012Validator


ROOT = Path(__file__).resolve().parents[1]


def test_every_published_schema_is_valid_and_indexed() -> None:
    contracts = (ROOT / "docs/SCHEMA_CONTRACTS.md").read_text(encoding="utf-8")
    schema_paths = sorted((ROOT / "schemas").glob("*.schema.json"))
    assert schema_paths
    for path in schema_paths:
        schema = json.loads(path.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        assert f"../schemas/{path.name})" in contracts, f"unindexed schema: {path.name}"


def test_legacy_program_index_schema_fields_match_tsv_headers() -> None:
    source = (ROOT / "ghidra/ExportGhidraProgramIndex.java").read_text(encoding="utf-8")
    expected = {
        "ghidra-program-index-functions-v1.schema.json": (
            r"entry\tname\taddress_count\tis_external\tsignature",
            ["entry", "name", "address_count", "is_external", "signature"],
        ),
        "ghidra-program-index-symbols-v1.schema.json": (
            r"address\tname\ttype\tsource\tis_primary",
            ["address", "name", "type", "source", "is_primary"],
        ),
        "ghidra-program-index-strings-v1.schema.json": (
            r"address\tutf8_base64\tlength",
            ["address", "utf8_base64", "length"],
        ),
        "ghidra-program-index-xrefs-v1.schema.json": (
            r"from\tto\ttype\toperand\tsource",
            ["from", "to", "type", "operand", "source"],
        ),
        "ghidra-program-index-calls-v1.schema.json": (
            r"caller_entry\tcall_site\tcallee_entry",
            ["caller_entry", "call_site", "callee_entry"],
        ),
    }
    for filename, (header, fields) in expected.items():
        schema = json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))
        assert header in source
        assert schema["required"] == fields
        assert list(schema["properties"]) == fields


def test_vtable_schema_matches_exported_tsv_columns() -> None:
    source = (ROOT / "ghidra/ExportArm32ItaniumVtableSlots.java").read_text(encoding="utf-8")
    schema = json.loads(
        (ROOT / "schemas/ghidra-arm32-itanium-vtable-slots-v1.schema.json").read_text(encoding="utf-8")
    )
    fields = [
        "vtable_symbol_start", "vtable_symbol_name", "address_point", "slot_offset",
        "slot_address", "raw_value", "target_thumb", "target_entry", "target_name",
        "target_signature", "resolution_mode", "next_vtable_symbol_start",
    ]
    assert schema["required"] == fields
    assert list(schema["properties"]) == fields
    assert all(field in source for field in fields)


def test_initial_report_and_plan_schemas_accept_current_outputs(tmp_path: Path) -> None:
    from revenginstr.family.mine import mine_dataset
    from revenginstr.ood.foreign_guard import apply_guard
    from revenginstr.pcode.audit import build_report
    from revenginstr.receiver.plan import build_plan

    def validate(filename: str, value: dict) -> None:
        schema = json.loads((ROOT / "schemas" / filename).read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(value)

    corpus_row = {
        "format": "REVENGINSTR.PcodeCorpus/1",
        "program": "sample.exe",
        "source_entry": "00401000",
        "source_name": "FUN_00401000",
        "external": False,
        "decompile_status": "failed",
        "error": "fixture failure",
    }
    validate("pcode-audit-v1.schema.json", build_report([corpus_row]))

    guarded, summary = apply_guard(
        [{"action": "accept", "base_action": None, "family_similarity": 0.2, "contrast_margin": 0.0}],
        0.70,
        0.05,
    )
    validate("foreign-guard-v1.schema.json", summary)
    validate("foreign-guard-row-v1.schema.json", guarded[0])

    trace = tmp_path / "trace.jsonl"
    trace.write_text(
        '{"program":"sample.exe","source_entry":"00000020"}\n'
        '{"program":"sample.exe","source_entry":"00000010"}\n',
        encoding="utf-8",
    )
    plan, _ = build_plan(trace)
    plan_schema = json.loads((ROOT / "schemas/receiver-plan-v1.schema.json").read_text(encoding="utf-8"))
    for source_id, entry in plan:
        Draft202012Validator(plan_schema).validate({
            "source_id": source_id,
            "source_entry": entry,
            "expected_calls": "",
        })
    assert [entry for _, entry in plan] == ["00000010", "00000020"]

    dataset = tmp_path / "dataset"
    dataset.mkdir()
    (dataset / "train.jsonl").write_text(
        json.dumps({"id": "sample:1000", "text": "ARCH=X8632\nENDIAN=LE\nPTR_SIZE=4\no0 INT_ADD out=v0:4\n"}) + "\n",
        encoding="utf-8",
    )
    output = tmp_path / "families.jsonl"
    manifest = mine_dataset(dataset, output)
    family_schema = json.loads((ROOT / "schemas/function-families-v1.schema.json").read_text(encoding="utf-8"))
    family_manifest_schema = json.loads((ROOT / "schemas/function-families-manifest-v1.schema.json").read_text(encoding="utf-8"))
    family_row = json.loads(output.read_text(encoding="utf-8"))
    Draft202012Validator(family_schema).validate(family_row)
    Draft202012Validator(family_manifest_schema).validate(manifest)
