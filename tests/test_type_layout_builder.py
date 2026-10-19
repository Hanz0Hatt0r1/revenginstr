from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.type_layout_builder import build_type_layout_hypotheses

ROOT = Path(__file__).resolve().parents[1]
PROGRAM_SHA256 = "a" * 64
LOAD_HEADER = (
    "format", "function_entry", "function_name", "load_address", "load_time",
    "base_parameter_index", "field_offset", "address_pattern", "value_size",
    "value_token", "status",
)


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def store_row(*, function: str, address: str, time: int, offset: int | None, width: int | None = 4,
              status: str = "parameter_rooted_constant_offset", root: int | None = 0) -> dict:
    return {
        "format": "REVENGINSTR.GhidraMemoryStoreAccess/1",
        "program_id": "sample.exe",
        "function_entry": function,
        "address": address,
        "time": time,
        "opcode": "STORE",
        "memory_space": "ram",
        "memory_physical_space": "ram",
        "memory_width_bytes": width,
        "memory_pointer_width_bytes": 8,
        "memory_space_size_bits": 64,
        "memory_addressable_unit_bytes": 1,
        "pointer_token": f"def:{address}:{time}:8",
        "root_parameter_index": root,
        "offset_bytes": offset,
        "location_status": status,
        "destination_pattern": "ptradd",
        "address_expression_ops": [],
    }


def member_row(*, function: str = "fn1", root: int = 0, type_id: str = "opaque-1") -> dict:
    return {
        "format": "REVENGINSTR.TypeLayoutMemberMap/1",
        "program_id": "sample.exe",
        "program_sha256": PROGRAM_SHA256,
        "type_id": type_id,
        "function_entry": function,
        "root_parameter_index": root,
    }


def field_type_review_row(*, offset: int = 0x20, kind: str = "data_pointer",
                          width: int | None = 8, target: str | None = "node") -> dict:
    return {
        "format": "REVENGINSTR.TypeLayoutFieldTypeReview/1",
        "program_id": "sample.exe",
        "program_sha256": PROGRAM_SHA256,
        "type_id": "opaque-1",
        "offset_bytes": offset,
        "kind": kind,
        "width_bytes": width,
        "target_type_id": target,
        "evidence": {
            "source_format": "sample.TypeEvidence/1",
            "source_sha256": "b" * 64,
            "record_key": f"offset={offset};kind={kind}",
            "source_pointer": f"evidence.jsonl#offset={offset}",
            "evidence_class": "exact_static",
        },
    }


def write_loads(path: Path, rows: list[list[str]]) -> None:
    path.write_text(
        "\t".join(LOAD_HEADER) + "\n" + "".join("\t".join(row) + "\n" for row in rows),
        encoding="utf-8",
    )


def build(store_path: Path, member_path: Path, load_path: Path | None = None) -> list[dict]:
    return build_type_layout_hypotheses(
        [store_path], [member_path],
        parameter_load_paths=[load_path] if load_path else None,
        program_id="sample.exe", program_sha256=PROGRAM_SHA256,
        language_id="x86:LE:64:default", pointer_width_bytes=8,
        addressable_unit_bytes=1, endianness="little",
    )


def test_builder_projects_exact_writes_and_bound_without_type_inference(tmp_path: Path) -> None:
    stores = tmp_path / "stores.jsonl"
    members = tmp_path / "members.jsonl"
    loads = tmp_path / "loads.tsv"
    write_jsonl(stores, [
        store_row(function="fn1", address="401000", time=2, offset=0x20),
        store_row(function="fn1", address="401004", time=4, offset=0x34),
        store_row(function="fn2", address="401010", time=6, offset=0x80),  # no member map
        store_row(function="fn1", address="401020", time=8, offset=None, status="unresolved"),
        store_row(function="fn1", address="401030", time=9, offset=-4),
    ])
    write_jsonl(members, [member_row()])
    write_loads(loads, [
        ["REVENGINSTR.GhidraParameterLoadField/1", "fn1", "getter", "401008", "10", "0",
         "0x20", "ptradd", "4", "def:LOAD@401008:10:4", "parameter_field_load"],
        ["REVENGINSTR.GhidraParameterLoadField/1", "fn1", "getter", "401040", "15", "0",
         "0x38", "ptradd", "2", "def:LOAD@401040:15:2", "parameter_field_load"],
        ["REVENGINSTR.GhidraParameterLoadField/1", "fn1", "getter", "401044", "18", "0",
         "-0x4", "ptradd", "4", "def:LOAD@401044:18:4", "parameter_field_load"],
        ["REVENGINSTR.GhidraParameterLoadField/1", "fn2", "other", "401050", "20", "0",
         "0x100", "ptradd", "4", "def:LOAD@401050:20:4", "parameter_field_load"],
    ])
    load_schema = json.loads((ROOT / "schemas/ghidra-parameter-load-field-v1.schema.json").read_text())
    Draft202012Validator.check_schema(load_schema)
    with loads.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle, delimiter="\t"):
            Draft202012Validator(load_schema).validate(row)

    rows = build(stores, members, loads)
    assert rows == build(stores, members, loads)
    assert len(rows) == 1
    row = rows[0]
    assert row["type_id"] == "opaque-1"
    assert [field["offset_bytes"] for field in row["fields"]] == [0x20, 0x34, 0x38]
    assert row["object_size"]["minimum_observed_bytes"] == 0x3A
    assert row["object_size"]["exact_size_bytes"] is None
    assert row["vtable_anchors"] == []
    assert row["relationships"] == []
    assert all(not field["type_candidates"] for field in row["fields"])
    assert {access["kind"] for access in row["fields"][0]["accesses"]} == {"read", "write"}
    read_evidence = [
        evidence
        for access in row["fields"][0]["accesses"] if access["kind"] == "read"
        for evidence in access["evidence"]
    ]
    assert {evidence["source_format"] for evidence in read_evidence} == {
        "REVENGINSTR.GhidraParameterLoadField/1", "REVENGINSTR.TypeLayoutMemberMap/1",
    }
    load_only = build_type_layout_hypotheses(
        [], [members], parameter_load_paths=[loads],
        program_id="sample.exe", program_sha256=PROGRAM_SHA256,
        language_id="x86:LE:64:default", pointer_width_bytes=8,
        addressable_unit_bytes=1, endianness="little",
    )[0]
    assert {field["offset_bytes"] for field in load_only["fields"]} == {0x20, 0x38}
    assert all(access["kind"] == "read" for field in load_only["fields"] for access in field["accesses"])
    assert load_only["object_size"]["minimum_observed_bytes"] == 0x3A
    assert {e["evidence_class"] for f in row["fields"] for a in f["accesses"] for e in a["evidence"]} == {
        "exact_static", "human_review",
    }
    schema = json.loads((ROOT / "schemas/type-layout-hypothesis-v1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(row)


def test_builder_rejects_duplicate_member_keys_and_program_mismatch(tmp_path: Path) -> None:
    stores = tmp_path / "stores.jsonl"
    members = tmp_path / "members.jsonl"
    write_jsonl(stores, [store_row(function="fn1", address="401000", time=2, offset=0x20)])
    write_jsonl(members, [member_row(), member_row(type_id="opaque-2")])
    with pytest.raises(ValueError, match="duplicate member-map join key"):
        build(stores, members)

    write_jsonl(members, [{**member_row(), "program_sha256": "b" * 64}])
    with pytest.raises(ValueError, match="program_sha256 does not match"):
        build(stores, members)


def test_builder_attaches_reviewed_field_types_only_to_observed_fields(tmp_path: Path) -> None:
    stores = tmp_path / "stores.jsonl"
    members = tmp_path / "members.jsonl"
    reviews = tmp_path / "field-types.jsonl"
    write_jsonl(stores, [
        store_row(function="fn1", address="401000", time=2, offset=0x20, width=8),
        store_row(function="fn1", address="401004", time=4, offset=0x24, width=1),
    ])
    write_jsonl(members, [member_row()])
    write_jsonl(reviews, [field_type_review_row(), field_type_review_row(
        offset=0x24, kind="boolean", width=1, target=None,
    )])

    rows = build_type_layout_hypotheses(
        [stores], [members], field_type_review_paths=[reviews],
        program_id="sample.exe", program_sha256=PROGRAM_SHA256,
        language_id="x86:LE:64:default", pointer_width_bytes=8,
        addressable_unit_bytes=1, endianness="little",
    )
    row = rows[0]
    fields = {field["offset_bytes"]: field for field in row["fields"]}
    assert fields[0x20]["status"] == "review"
    assert fields[0x20]["type_candidates"] == [{
            "kind": "data_pointer", "width_bytes": 8, "target_type_id": "node",
            "evidence": [
                {
                    "source_format": "REVENGINSTR.TypeLayoutFieldTypeReview/1",
                    "source_sha256": hashlib.sha256(reviews.read_bytes()).hexdigest(),
                    "record_key": "type_id=opaque-1;offset_bytes=32;kind=data_pointer;"
                    "width_bytes=8;target_type_id=node",
                    "source_pointer": "field-types.jsonl#line=1", "evidence_class": "human_review",
                },
                {
                    "source_format": "sample.TypeEvidence/1", "source_sha256": "b" * 64,
                    "record_key": "offset=32;kind=data_pointer",
                    "source_pointer": "evidence.jsonl#offset=32", "evidence_class": "exact_static",
                },
        ],
    }]
    assert fields[0x24]["status"] == "review"
    assert fields[0x24]["type_candidates"][0]["kind"] == "boolean"
    assert fields[0x24]["type_candidates"][0]["width_bytes"] == 1
    review_schema = json.loads((ROOT / "schemas/type-layout-field-type-review-v1.schema.json").read_text())
    output_schema = json.loads((ROOT / "schemas/type-layout-hypothesis-v1.schema.json").read_text())
    Draft202012Validator.check_schema(review_schema)
    Draft202012Validator(review_schema).validate(field_type_review_row())
    Draft202012Validator(output_schema).validate(row)


def test_builder_preserves_conflicting_field_type_reviews(tmp_path: Path) -> None:
    stores = tmp_path / "stores.jsonl"
    members = tmp_path / "members.jsonl"
    reviews = tmp_path / "field-types.jsonl"
    write_jsonl(stores, [store_row(function="fn1", address="401000", time=2, offset=0x20)])
    write_jsonl(members, [member_row()])
    write_jsonl(reviews, [
        field_type_review_row(),
        field_type_review_row(kind="integer", width=4, target=None),
    ])

    row = build_type_layout_hypotheses(
        [stores], [members], field_type_review_paths=[reviews],
        program_id="sample.exe", program_sha256=PROGRAM_SHA256,
        language_id="x86:LE:64:default", pointer_width_bytes=8,
        addressable_unit_bytes=1, endianness="little",
    )[0]
    field = row["fields"][0]
    assert row["status"] == field["status"] == "conflicted"
    assert {candidate["kind"] for candidate in field["type_candidates"]} == {"data_pointer", "integer"}
    assert field["conflicts"][0]["reason"] == "evidence_conflict"
    assert row["conflicts"][0]["reason"] == "evidence_conflict"
    schema = json.loads((ROOT / "schemas/type-layout-hypothesis-v1.schema.json").read_text())
    Draft202012Validator(schema).validate(row)


def test_builder_rejects_unobserved_field_and_pointer_width_mismatch(tmp_path: Path) -> None:
    stores = tmp_path / "stores.jsonl"
    members = tmp_path / "members.jsonl"
    reviews = tmp_path / "field-types.jsonl"
    write_jsonl(stores, [store_row(function="fn1", address="401000", time=2, offset=0x20)])
    write_jsonl(members, [member_row()])

    write_jsonl(reviews, [field_type_review_row(offset=0x24)])
    with pytest.raises(ValueError, match="do not match an observed mapped field"):
        build_type_layout_hypotheses(
            [stores], [members], field_type_review_paths=[reviews],
            program_id="sample.exe", program_sha256=PROGRAM_SHA256,
            language_id="x86:LE:64:default", pointer_width_bytes=8,
            addressable_unit_bytes=1, endianness="little",
        )

    write_jsonl(reviews, [field_type_review_row(width=4)])
    with pytest.raises(ValueError, match="pointer width does not match"):
        build_type_layout_hypotheses(
            [stores], [members], field_type_review_paths=[reviews],
            program_id="sample.exe", program_sha256=PROGRAM_SHA256,
            language_id="x86:LE:64:default", pointer_width_bytes=8,
            addressable_unit_bytes=1, endianness="little",
        )


def test_nfs_shift_reviewed_member_map_replays_exact_field_evidence() -> None:
    evidence_root = ROOT / (
        "docs/evidence/receiver-field-access/nfs-shift-screening-20261019/"
        "scan37/replay-0041dd40"
    )
    stores = evidence_root / "field20-memory-store-access.jsonl"
    loads = evidence_root / "field20-parameter-loads.tsv"
    members = evidence_root / "nfs-shift-member-map.jsonl"
    binary_sha256 = "eca479aa2d8dbb88bc55709d91ae5c7159ae1b00fc9555d6701000c26de8aee1"
    member_schema = json.loads((ROOT / "schemas/type-layout-member-map-v1.schema.json").read_text())
    Draft202012Validator.check_schema(member_schema)
    for line in members.read_text(encoding="utf-8").splitlines():
        Draft202012Validator(member_schema).validate(json.loads(line))
    load_schema = json.loads((ROOT / "schemas/ghidra-parameter-load-field-v1.schema.json").read_text())
    Draft202012Validator.check_schema(load_schema)
    with loads.open(encoding="utf-8", newline="") as handle:
        for load_row in csv.DictReader(handle, delimiter="\t"):
            Draft202012Validator(load_schema).validate(load_row)
    rows = build_type_layout_hypotheses(
        [stores], [members], parameter_load_paths=[loads],
        program_id="nfs-shift:SHIFT.exe", program_sha256=binary_sha256,
        language_id="x86:LE:32:default", pointer_width_bytes=4,
        addressable_unit_bytes=1, endianness="little",
    )
    assert len(rows) == 1
    row = rows[0]
    assert row["type_id"] == "cluster-vtable-00af0860"
    fields = {field["offset_bytes"]: field for field in row["fields"]}
    assert 0x20 in fields
    field20_accesses = fields[0x20]["accesses"]
    field20_writes = [access for access in field20_accesses if access["kind"] == "write"]
    field20_reads = [access for access in field20_accesses if access["kind"] == "read"]
    store_records = {
        evidence["record_key"]
        for access in field20_writes
        for evidence in access["evidence"]
        if evidence["source_format"] == "REVENGINSTR.GhidraMemoryStoreAccess/1"
    }
    assert len(store_records) == 4
    load_records = {
        evidence["record_key"]
        for access in field20_reads
        for evidence in access["evidence"]
        if evidence["source_format"] == "REVENGINSTR.GhidraParameterLoadField/1"
    }
    assert load_records == {"function=009d1880;address=009d1880;time=1;output=def:LOAD@009d1880:1:4"}
    assert row["object_size"]["minimum_observed_bytes"] == 56
    assert row["object_size"]["exact_size_bytes"] is None
    assert row["vtable_anchors"] == []
    assert row["fields"] and all(field["type_candidates"] == [] for field in row["fields"])
    output_schema = json.loads((ROOT / "schemas/type-layout-hypothesis-v1.schema.json").read_text())
    Draft202012Validator.check_schema(output_schema)
    Draft202012Validator(output_schema).validate(row)
    built_output = evidence_root / "type-layout-builder-output.jsonl"
    assert json.loads(built_output.read_text(encoding="utf-8")) == row
    manifest_path = ROOT / "docs/evidence/receiver-field-access/nfs-shift-screening-20261019/manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for path in (loads, members, built_output):
        relative = path.relative_to(manifest_path.parent).as_posix()
        artifact = next(item for item in manifest["artifacts"] if item["path"] == relative)
        content = path.read_bytes()
        assert artifact["bytes"] == len(content)
        assert artifact["sha256"] == hashlib.sha256(content).hexdigest()
        declared_rows = len(content.decode("utf-8").splitlines()) - (1 if path.suffix == ".tsv" else 0)
        assert artifact["rows"] == declared_rows
