from __future__ import annotations

import hashlib
import json
import struct
import zipfile
import csv
import gzip
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.android_jni_prototypes import (
    export_android_jni_prototypes,
    validate_row,
)
from revenginstr.prototype_evaluation import evaluate_prototypes
from revenginstr.prototype_inference import infer_prototypes

ROOT = Path(__file__).resolve().parents[1]


def _uleb(value: int) -> bytes:
    result = bytearray()
    while True:
        byte = value & 0x7f
        value >>= 7
        result.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(result)


def _minimal_dex() -> bytes:
    descriptors = [
        "I", "J", "Lcom/example/Native;", "Ljava/lang/Object;", "V",
    ]
    method_name = "nativeCall"
    shorty = "IJ"
    strings = sorted(set(descriptors + [method_name, shorty]))
    string_index = {value: index for index, value in enumerate(strings)}
    types = sorted(descriptors, key=lambda value: string_index[value])
    type_index = {value: index for index, value in enumerate(types)}

    string_count, type_count = len(strings), len(types)
    string_ids_off = 0x70
    type_ids_off = string_ids_off + string_count * 4
    proto_ids_off = type_ids_off + type_count * 4
    method_ids_off = proto_ids_off + 12
    class_defs_off = method_ids_off + 8
    data_off = (class_defs_off + 32 + 3) & ~3
    data = bytearray()

    string_data_offsets = {}
    for value in strings:
        string_data_offsets[value] = data_off + len(data)
        encoded = value.encode("utf-8")
        data.extend(_uleb(len(value)))
        data.extend(encoded)
        data.append(0)

    while (data_off + len(data)) % 4:
        data.append(0)
    parameters_off = data_off + len(data)
    data.extend(struct.pack("<I H", 1, type_index["I"]))
    while (data_off + len(data)) % 4:
        data.append(0)
    class_data_off = data_off + len(data)
    data.extend(b"\x00\x00\x01\x00")
    data.extend(_uleb(0))
    data.extend(_uleb(0x109))  # public static native
    data.extend(_uleb(0))

    class_index = type_index["Lcom/example/Native;"]
    code = bytearray(data_off)
    code[:8] = b"dex\n035\x00"
    struct.pack_into("<I", code, 0x24, 0x70)
    struct.pack_into("<I", code, 0x28, 0x12345678)
    struct.pack_into("<II", code, 0x38, string_count, string_ids_off)
    struct.pack_into("<II", code, 0x40, type_count, type_ids_off)
    struct.pack_into("<II", code, 0x48, 1, proto_ids_off)
    struct.pack_into("<II", code, 0x58, 1, method_ids_off)
    struct.pack_into("<II", code, 0x60, 1, class_defs_off)
    struct.pack_into("<II", code, 0x68, len(data), data_off)
    for index, value in enumerate(strings):
        struct.pack_into("<I", code, string_ids_off + index * 4, string_data_offsets[value])
    for index, value in enumerate(types):
        struct.pack_into("<I", code, type_ids_off + index * 4, string_index[value])
    struct.pack_into(
        "<III", code, proto_ids_off, string_index[shorty], type_index["J"], parameters_off,
    )
    struct.pack_into(
        "<HHI", code, method_ids_off, class_index, 0, string_index[method_name],
    )
    struct.pack_into(
        "<IIIIIIII", code, class_defs_off, class_index, 1, type_index["Ljava/lang/Object;"],
        0, 0xffffffff, 0, class_data_off, 0,
    )
    code.extend(data)
    struct.pack_into("<I", code, 0x20, len(code))
    return bytes(code)


def _decompiler_row(binary_sha: str) -> dict:
    return {
        "format": "REVENGINSTR.GhidraDecompilerParameters/1",
        "plan_id": "nativeCall",
        "program_id": "libfixture.so",
        "program_sha256": binary_sha,
        "architecture": {"language_id": "ARM:LE:32:v8", "pointer_width_bytes": 4, "endianness": "little"},
        "requested_entry": "00401000",
        "function_entry": "00401000",
        "name": "Java_com_example_Native_nativeCall",
        "is_external": False,
        "status": "complete",
        "signature_source": "DEFAULT",
        "calling_convention": "unknown",
        "has_varargs": False,
        "parameter_count": 1,
        "parameters": [{
            "index": 0, "name": "param_1",
            "type": {"kind": "unknown", "name": "undefined4", "path": "/undefined4", "width_bytes": 4},
            "storage": "R0:4", "is_this_pointer": False, "is_hidden_return": False,
            "is_type_locked": False,
        }],
        "return_type": {"kind": "unknown", "name": "undefined4", "path": "/undefined4", "width_bytes": 4},
        "return_storage": "R0:4",
        "error": None,
    }


def _gold_from_evidence(row: dict) -> dict:
    return {
        "format": "REVENGINSTR.FunctionPrototypeGold/1",
        "dataset_id": "synthetic-android-jni",
        "split_id": "one-method-v1",
        "program_id": row["program_id"],
        "program_sha256": row["program_sha256"],
        "architecture": row["architecture"],
        "function_entry": row["function_entry"],
        "complete_properties": ["parameter_count", "return_value"],
        "complete_parameter_indices": list(range(row["parameter_count"])),
        "compatible_prototypes": [{
            "parameter_count": row["parameter_count"],
            "calling_convention": None,
            "parameters": [
                {"index": item["index"], "kind": item["kind"], "width_bytes": item["width_bytes"]}
                for item in row["parameters"]
            ],
            "return_value": row["return_value"],
            "receiver_parameter_index": row["receiver_parameter_index"],
        }],
        "evidence_refs": row["evidence_refs"],
        "adjudication_status": "adjudicated",
    }


def test_dex_jni_evidence_recovers_implicit_parameters_and_exact_shapes(tmp_path: Path) -> None:
    dex = _minimal_dex()
    library = b"synthetic native library bytes"
    apk = tmp_path / "fixture.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("classes.dex", dex)
        archive.writestr("lib/armeabi-v7a/libfixture.so", library)

    index = tmp_path / "functions.tsv"
    index.write_text(
        "entry\tname\taddress_count\tis_external\tsignature\n"
        "00000000\tJava_com_example_Native_nativeCall\t0\ttrue\tundefined undefined(void)\n"
        "00401000\tJava_com_example_Native_nativeCall\t4\tfalse\tundefined undefined(void)\n",
        encoding="utf-8",
    )
    decompiler = tmp_path / "decompiler.jsonl"
    decompiler.write_text(json.dumps(_decompiler_row(hashlib.sha256(library).hexdigest())) + "\n")

    rows, counts = export_android_jni_prototypes(apk, index, decompiler)
    assert counts == {
        "dex_native_methods": 1, "matching_exported_symbols": 1,
        "selected_functions": 1, "ambiguous_symbols": 0,
    }
    assert len(rows) == 1
    evidence = rows[0]
    assert evidence["evidence_refs"][1]["record_index"] == 2
    validate_row(evidence, "synthetic DEX")
    assert evidence["method_descriptor"] == "(I)J"
    assert evidence["parameter_count"] == 3
    assert [parameter["kind"] for parameter in evidence["parameters"]] == [
        "pointer", "pointer", "scalar",
    ]
    assert evidence["return_value"] == {"kind": "scalar", "width_bytes": 8}

    schema = json.loads(
        (ROOT / "schemas/android-jni-prototype-evidence-v1.schema.json").read_text()
    )
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(evidence)

    direct_calls = tmp_path / "calls.jsonl"
    direct_calls.write_text("", encoding="utf-8")
    decompiler.write_text(json.dumps(_decompiler_row(hashlib.sha256(library).hexdigest())) + "\n")
    jni_path = tmp_path / "jni.jsonl"
    jni_path.write_text(json.dumps(evidence) + "\n", encoding="utf-8")
    inferred = infer_prototypes(decompiler, direct_calls, android_jni_evidence_path=jni_path)
    assert inferred[0]["status"] == "candidate"
    candidate = inferred[0]["candidates"][0]
    assert candidate["confidence"] == 1.0
    assert candidate["parameter_count"] == 3
    assert [parameter["kind"] for parameter in candidate["parameters"]] == [
        "pointer", "pointer", "scalar",
    ]
    assert candidate["return_value"] == {"kind": "scalar", "width_bytes": 8}
    gold = _gold_from_evidence(evidence)
    hypotheses_path = tmp_path / "hypotheses.jsonl"
    hypotheses_path.write_text(json.dumps(inferred[0]) + "\n", encoding="utf-8")
    gold_path = tmp_path / "gold.jsonl"
    gold_path.write_text(json.dumps(gold) + "\n", encoding="utf-8")
    report = evaluate_prototypes(hypotheses_path, gold_path, minimum_confidence=0.95, format_version=2)
    assert report["high_confidence_function_coverage"] == 1.0
    assert report["high_confidence_candidate_compatibility"] == 1.0


def test_dex_evidence_rejects_an_apk_with_the_wrong_native_library(tmp_path: Path) -> None:
    dex = _minimal_dex()
    apk = tmp_path / "wrong.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("classes.dex", dex)
        archive.writestr("lib/armeabi-v7a/libfixture.so", b"different native bytes")
    index = tmp_path / "functions.tsv"
    index.write_text(
        "entry\tname\taddress_count\tis_external\tsignature\n"
        "00401000\tJava_com_example_Native_nativeCall\t4\tfalse\tundefined undefined(void)\n",
        encoding="utf-8",
    )
    decompiler = tmp_path / "decompiler.jsonl"
    decompiler.write_text(json.dumps(_decompiler_row("a" * 64)) + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="no native library matches"):
        export_android_jni_prototypes(apk, index, decompiler)


def test_nonstatic_jni_method_is_marked_as_receiver() -> None:
    from revenginstr.android_jni_prototypes import _shape_for_method

    parameters, return_value, receiver = _shape_for_method({
        "class_descriptor": "Lcom/example/Native;", "method_name": "read",
        "method_descriptor": "()[Ljava/lang/String;", "is_static": False,
    }, 8)
    assert parameters == [
        {"index": 0, "role": "jni_environment", "java_parameter_index": None, "kind": "pointer", "width_bytes": 8},
        {"index": 1, "role": "jni_receiver", "java_parameter_index": None, "kind": "pointer", "width_bytes": 8},
    ]
    assert receiver == 1
    assert return_value == {"kind": "pointer", "width_bytes": 8}


def test_nevergone_jni_replay_reproduces_baseline_and_exact_source_results() -> None:
    fixture = ROOT / "tests/fixtures/nevergone-android-jni-prototype"
    evidence = [json.loads(line) for line in (fixture / "android-jni-prototypes.jsonl").read_text().splitlines()]
    gold = [json.loads(line) for line in (fixture / "gold.jsonl").read_text().splitlines()]
    schema = json.loads(
        (ROOT / "schemas/android-jni-prototype-evidence-v1.schema.json").read_text()
    )
    validator = Draft202012Validator(schema)
    assert len(evidence) == len(gold) == 21
    assert {row["apk_sha256"] for row in evidence} == {
        "97296efc9d32fdd46bdf2dba475aeb13adb4cc6d2957ddf02da7a5d9c56e9508",
    }
    assert {row["program_sha256"] for row in evidence} == {
        "94b1ef6a9469e261183ac08199c5b0eb65c0c40b81918ca097bd32920828eb5e",
    }
    for row in evidence:
        validator.validate(row)

    function_index = fixture / "program-functions.tsv.gz"
    index_sha = hashlib.sha256(function_index.read_bytes()).hexdigest()
    with gzip.open(function_index, "rt", newline="") as handle:
        function_rows = list(csv.DictReader(handle, delimiter="\t"))
    for row in evidence:
        index_ref = row["evidence_refs"][1]
        assert index_ref["artifact_sha256"] == index_sha
        function = function_rows[index_ref["record_index"] - 1]
        assert function["entry"] == row["function_entry"]
        assert function["name"] == row["jni_symbol"]

    baseline = infer_prototypes(
        fixture / "decompiler-parameters.jsonl", fixture / "direct-call-observations.jsonl",
    )
    expected_baseline = [
        json.loads(line) for line in (fixture / "baseline-hypotheses.jsonl").read_text().splitlines()
    ]
    assert baseline == expected_baseline
    baseline_report = evaluate_prototypes(
        fixture / "baseline-hypotheses.jsonl", fixture / "gold.jsonl",
        minimum_confidence=0.95, format_version=2,
    )
    assert baseline_report == json.loads((fixture / "baseline-evaluation.json").read_text())
    assert baseline_report["per_property"]["parameter_count"]["compatible"] == 11
    assert baseline_report["per_property"]["parameters"]["coverage"] == 0

    improved = infer_prototypes(
        fixture / "decompiler-parameters.jsonl", fixture / "direct-call-observations.jsonl",
        android_jni_evidence_path=fixture / "android-jni-prototypes.jsonl",
    )
    expected_improved = [json.loads(line) for line in (fixture / "hypotheses.jsonl").read_text().splitlines()]
    assert improved == expected_improved
    improved_report = evaluate_prototypes(
        fixture / "hypotheses.jsonl", fixture / "gold.jsonl",
        minimum_confidence=0.95, format_version=2,
    )
    assert improved_report == json.loads((fixture / "improved-evaluation.json").read_text())
    assert improved_report["high_confidence_function_coverage"] == 1
    assert improved_report["high_confidence_candidate_compatibility"] == 1
    assert all(row["status"] == "candidate" for row in improved)
