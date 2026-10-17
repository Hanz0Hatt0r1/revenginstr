from __future__ import annotations

import csv
import gzip
import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.benchmark import TOOLS
from revenginstr.effect_ir import build_function_effect_ir
from revenginstr.object_role_features import (
    MANIFEST_FORMAT,
    VTABLE_HEADER,
    build_object_role_feature_set,
    main,
)
from revenginstr.receiver.infer import infer

ROOT = Path(__file__).resolve().parents[1]
STORE_FIXTURE = ROOT / "tests/fixtures/parameter-field/parameter-stores.tsv"
LOAD_FIXTURE = ROOT / "tests/fixtures/parameter-field/parameter-loads.tsv"
PCODE_FIXTURE = ROOT / "tests/fixtures/receiver-flow-pcode.tsv"
FEATURE_SCHEMA = json.loads((ROOT / "schemas/object-role-feature-set-v1.schema.json").read_text())
MANIFEST_SCHEMA = json.loads((ROOT / "schemas/object-role-feature-extraction-manifest-v1.schema.json").read_text())


def effect_rows() -> list[dict]:
    return build_function_effect_ir(
        "sample:analysis",
        parameter_store_tsv=STORE_FIXTURE,
        parameter_load_tsv=LOAD_FIXTURE,
        pcode_flow_tsv=PCODE_FIXTURE,
    )


def receiver_rows() -> list[dict]:
    return infer(
        [{
            "format": "REVENGINSTR.GhidraIndirectReceiverType/1",
            "source_id": "sample:00401000",
            "call_index": "0",
            "call_address": "00401010",
            "receiver_pointer_depth": "1",
            "pointee_type_name": "FixtureType",
            "pointee_type_display": "FixtureType",
            "receiver_type_name": "FixtureType *",
            "receiver_type_display": "FixtureType *",
            "receiver_storage_kind": "register",
            "flow_type_node_count": "1",
            "flow_single_pointer_pointee_names_json": "[]",
            "flow_single_pointer_pointee_displays_json": "[]",
        }],
        [{"format": "fixture.catalog/1", "class_name": "FixtureType", "receiver_vtable_id": "fixture:vtable:1"}],
    )


def vtable_rows() -> list[dict[str, str]]:
    return [{
        "vtable_symbol_start": "0x1000", "vtable_symbol_name": "vtable_fixture",
        "address_point": "0x1008", "slot_offset": "0x4", "slot_address": "0x100c",
        "raw_value": "0x401001", "target_thumb": "true", "target_entry": "00401000",
        "target_name": "FUN_00401000", "target_signature": "void(void)",
        "resolution_mode": "direct_ghidra_address", "next_vtable_symbol_start": "-",
    }]


def callgraph_rows() -> list[dict]:
    return [
        {
            "format": "REVENGINSTR.CallGraphMetrics/1", "id": "fixture:00401000",
            "source_entry": "00401000", "metrics": {"fan_in": 3, "fan_out": 2},
        },
        {
            "format": "REVENGINSTR.CallGraphMetrics/1", "id": "fixture:00402100",
            "source_entry": "00402100", "metrics": {"fan_in": 1, "fan_out": 0},
        },
    ]


def test_object_role_feature_extractor_uses_all_generic_evidence_groups() -> None:
    effects = effect_rows()
    receiver = receiver_rows()
    vtables = vtable_rows()
    metrics = callgraph_rows()
    feature_rows, manifest = build_object_role_feature_set(
        effects,
        effect_ir_sha256="a" * 64,
        receiver_rows=receiver,
        receiver_sha256="b" * 64,
        vtable_rows=vtables,
        vtable_sha256="c" * 64,
        callgraph_rows=metrics,
        callgraph_sha256="d" * 64,
    )

    for row in feature_rows:
        Draft202012Validator(FEATURE_SCHEMA).validate(row)
    Draft202012Validator.check_schema(MANIFEST_SCHEMA)
    Draft202012Validator(MANIFEST_SCHEMA).validate(manifest)
    by_entry = {row["function_entry"]: row for row in feature_rows}
    groups = {row["function_entry"]: {feature["group"] for feature in row["features"]} for row in feature_rows}
    assert groups["00401000"] == {"effect_ir", "field", "receiver", "vtable_slot", "callgraph"}
    assert "callgraph" in groups["00402000"]
    assert "callgraph" in groups["00402100"]
    assert manifest["format"] == MANIFEST_FORMAT
    assert manifest["input_artifacts"]["function_effect_ir"]["row_count"] == 2
    assert manifest["input_artifacts"]["vtable_slots"]["sha256"] == "c" * 64
    serialized = json.dumps(feature_rows)
    assert "FixtureType" not in serialized
    assert "FUN_00401000" not in serialized
    assert by_entry["00401000"]["program_id"] == "sample:analysis"


def test_object_role_features_use_v2_memory_kinds_without_operand_tokens(tmp_path: Path) -> None:
    pcode_path = tmp_path / "pcode-v2.tsv"
    pcode_path.write_bytes(
        PCODE_FIXTURE.read_bytes()
        + b"00401000\t00401028\t10\tSTORE\t-\tconst:ram:4;register:0010:4;const:0x1:4\t-\t-\n"
    )
    effects = build_function_effect_ir(
        "sample:analysis", pcode_flow_tsv=pcode_path, include_generic_memory_ops=True
    )
    effect_bytes = "".join(json.dumps(row, sort_keys=True) + "\n" for row in effects).encode()

    feature_rows, manifest = build_object_role_feature_set(
        effects, effect_ir_sha256=hashlib.sha256(effect_bytes).hexdigest()
    )

    function_features = next(
        row["features"] for row in feature_rows if row["function_entry"] == "00401000"
    )
    effect_hashes = {
        feature["feature_sha256"] for feature in function_features if feature["group"] == "effect_ir"
    }
    expected = {
        hashlib.sha256(f"effect_ir\0kind:{kind}".encode()).hexdigest()
        for kind in ("memory_read", "memory_write")
    }
    assert expected <= effect_hashes
    assert manifest["input_artifacts"]["function_effect_ir"]["sha256"] == hashlib.sha256(
        effect_bytes
    ).hexdigest()
    serialized = json.dumps(feature_rows)
    assert "register:0010:4" not in serialized
    assert "const:ram:4" not in serialized


def test_object_role_feature_extractor_rejects_unknown_receiver_status() -> None:
    receiver = receiver_rows()
    receiver[0]["status"] = "provisional"
    with pytest.raises(ValueError, match="unsupported status"):
        build_object_role_feature_set(
            effect_rows(), effect_ir_sha256="a" * 64,
            receiver_rows=receiver, receiver_sha256="b" * 64,
        )


def test_object_role_feature_cli_writes_jsonl_and_hash_manifest(tmp_path: Path, capsys) -> None:
    assert TOOLS["object-role-features"] == ("revenginstr.object_role_features", "main")
    effects_path = tmp_path / "effects.jsonl"
    effects = effect_rows()
    effects_path.write_text("".join(json.dumps(row) + "\n" for row in effects), encoding="utf-8")
    receiver_path = tmp_path / "receivers.jsonl"
    receiver_path.write_text("".join(json.dumps(row) + "\n" for row in receiver_rows()), encoding="utf-8")
    metrics_path = tmp_path / "metrics.jsonl"
    metrics_path.write_text("".join(json.dumps(row) + "\n" for row in callgraph_rows()), encoding="utf-8")
    slots_path = tmp_path / "slots.tsv.gz"
    with gzip.open(slots_path, "wt", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=VTABLE_HEADER, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerows(vtable_rows())
    output = tmp_path / "nested" / "features.jsonl"

    assert main([
        str(effects_path), "--receiver-inference", str(receiver_path),
        "--vtable-slots-tsv", str(slots_path), "--callgraph-metrics", str(metrics_path),
        "--output", str(output),
    ]) == 0

    rows = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]
    for row in rows:
        Draft202012Validator(FEATURE_SCHEMA).validate(row)
    manifest_path = output.with_suffix(output.suffix + ".manifest.json")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    Draft202012Validator(MANIFEST_SCHEMA).validate(manifest)
    assert manifest["input_artifacts"]["function_effect_ir"]["sha256"] == hashlib.sha256(
        effects_path.read_bytes()
    ).hexdigest()
    assert manifest["input_artifacts"]["vtable_slots"]["row_count"] == 1
    assert "features:" in capsys.readouterr().out


def test_object_role_feature_cli_refuses_to_overwrite_an_input(tmp_path: Path) -> None:
    source = tmp_path / "effects.jsonl"
    source.write_text("".join(json.dumps(row) + "\n" for row in effect_rows()), encoding="utf-8")
    original = source.read_bytes()
    with pytest.raises(ValueError, match="overlaps an input"):
        main([str(source), "--output", str(source)])
    assert source.read_bytes() == original
