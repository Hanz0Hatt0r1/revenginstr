from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.indirect_call_slots import (
    CALL_EVIDENCE_FORMAT,
    FORMAT,
    PROVENANCE_FORMAT,
    build_indirect_call_pointer_slots,
)

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schemas/indirect-call-pointer-slot-v1.schema.json").read_text())
PROGRAM = "synthetic:binary"
FUNCTION = "00401000"
CALL_ADDRESS = "00401040"
LOAD_ADDRESS = "00401020"
TARGET = f"def:LOAD@{LOAD_ADDRESS}:7:4"
P_CODE_HASH = hashlib.sha256(b"synthetic P-code").hexdigest()


def write_inputs(
    tmp_path: Path,
    *,
    alternatives: list[dict] | None = None,
    load_status: str = "resolved",
    include_target_provenance: bool = True,
    target_source_hash: str | None = None,
    target: str | None = None,
    target_opcode: str = "LOAD",
    target_output_token: str | None = None,
) -> tuple[Path, Path]:
    callind_path = tmp_path / "callind.jsonl"
    callind = {
        "format": CALL_EVIDENCE_FORMAT,
        "program": "SYNTH.exe",
        "requested": FUNCTION,
        "function_entry": FUNCTION,
        "call_address": CALL_ADDRESS,
        "call_time": 12,
        "target": target or f"def:{target_opcode}@{LOAD_ADDRESS}:7:4",
        "target_expression": "LOAD(CAST(INT_ADD(LOAD(this),const:0x10)))",
        "arg_count": 1,
    }
    callind_path.write_text(json.dumps(callind) + "\n", encoding="utf-8")
    callind_hash = hashlib.sha256(callind_path.read_bytes()).hexdigest()
    flow_source = {
        "source_format": "REVENGINSTR.GhidraFunctionPcodeFlow/1",
        "artifact_path": "flow.tsv",
        "artifact_sha256": P_CODE_HASH,
        "record_index": 4,
    }
    callind_source = {
        "source_format": CALL_EVIDENCE_FORMAT,
        "artifact_path": str(callind_path),
        "artifact_sha256": target_source_hash or callind_hash,
        "record_index": 1,
    }
    rows: list[dict] = []
    if include_target_provenance:
        rows.append({
            "format": PROVENANCE_FORMAT,
            "record_kind": "callind_target",
            "evidence_class": "derived_structural",
            "program_id": PROGRAM,
            "function_entry": FUNCTION,
            "operation_address": CALL_ADDRESS,
            "operation_time": 12,
            "opcode": "CALLIND",
            "output_token": target_output_token or f"def:{LOAD_ADDRESS}:7:4",
            "status": "load_anchor",
            "alternatives": [],
            "load_address": None,
            "source": flow_source,
            "target_source": callind_source,
        })
        rows.append({
            "format": PROVENANCE_FORMAT,
            "record_kind": "operation_output",
            "evidence_class": "derived_structural",
            "program_id": PROGRAM,
            "function_entry": FUNCTION,
            "operation_address": LOAD_ADDRESS,
            "operation_time": 7,
            "opcode": target_opcode,
            "output_token": f"def:{LOAD_ADDRESS}:7:4",
            "status": "load_anchor",
            "alternatives": [],
            "load_address": {
                "address_token": "def:00401020:6:4",
                "space_token": "const:0x1a1:4",
                "status": load_status,
                "alternatives": alternatives if alternatives is not None else [{
                    "root_kind": "memory_read_anchor",
                    "root_id": "memory:00401000:00401010#3",
                    "offset_bytes": 16,
                    "pointer_size_bytes": 4,
                    "status": "resolved",
                }],
            } if target_opcode == "LOAD" else None,
            "source": flow_source,
            "target_source": None,
        })
    provenance_path = tmp_path / "provenance.jsonl"
    provenance_path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
    return provenance_path, callind_path


def analyze(tmp_path: Path, **kwargs) -> dict:
    provenance, callind = write_inputs(tmp_path, **kwargs)
    rows = build_indirect_call_pointer_slots(
        [provenance], [callind], program_id=PROGRAM,
    )
    assert len(rows) == 1
    Draft202012Validator(SCHEMA).validate(rows[0])
    return rows[0]


def test_exact_load_provenance_emits_aligned_slot_candidate(tmp_path: Path) -> None:
    row = analyze(tmp_path)
    assert row["format"] == FORMAT
    assert row["status"] == "slot_access_candidate"
    assert row["slot_access"] == {
        "base_root_kind": "memory_read_anchor",
        "base_root_id": "memory:00401000:00401010#3",
        "offset_bytes": 16,
        "pointer_size_bytes": 4,
    }
    assert row["source"]["callind_target_provenance"]["record_index"] == 1
    assert row["source"]["target_definition_provenance"]["record_index"] == 2


def test_signed_aligned_slot_offset_is_preserved(tmp_path: Path) -> None:
    row = analyze(tmp_path, alternatives=[{
        "root_kind": "address_anchor", "root_id": "const:0x1000:4",
        "offset_bytes": -8, "pointer_size_bytes": 4, "status": "resolved",
    }])
    assert row["status"] == "slot_access_candidate"
    assert row["slot_access"]["offset_bytes"] == -8


@pytest.mark.parametrize(
    ("kwargs", "status"),
    [
        ({"alternatives": [
            {"root_kind": "memory_read_anchor", "root_id": "a", "offset_bytes": 0, "pointer_size_bytes": 4, "status": "resolved"},
            {"root_kind": "memory_read_anchor", "root_id": "b", "offset_bytes": 4, "pointer_size_bytes": 4, "status": "resolved"},
        ]}, "ambiguous_address"),
        ({"load_status": "unknown"}, "unresolved_address"),
        ({"alternatives": [{
            "root_kind": "memory_read_anchor", "root_id": "a", "offset_bytes": 4,
            "pointer_size_bytes": 8, "status": "resolved",
        }]}, "width_mismatch"),
        ({"alternatives": [{
            "root_kind": "memory_read_anchor", "root_id": "a", "offset_bytes": 2,
            "pointer_size_bytes": 4, "status": "resolved",
        }]}, "unaligned_slot_offset"),
    ],
)
def test_ambiguous_or_unsupported_loads_fail_closed(tmp_path: Path, kwargs: dict, status: str) -> None:
    row = analyze(tmp_path, **kwargs)
    assert row["status"] == status
    assert row["slot_access"] is None


def test_missing_exact_provenance_is_explicit(tmp_path: Path) -> None:
    row = analyze(tmp_path, include_target_provenance=False)
    assert row["status"] == "missing_target_provenance"
    assert row["slot_access"] is None
    assert row["source"]["callind_target_provenance"] is None


def test_non_load_target_definition_stays_out_of_slot_candidates(tmp_path: Path) -> None:
    row = analyze(
        tmp_path,
        target_opcode="INT_ADD",
        target_output_token=f"def:{LOAD_ADDRESS}:7:4",
    )
    assert row["status"] == "unsupported_target_operation"
    assert row["slot_access"] is None
    assert row["source"]["target_definition_provenance"]["record_index"] == 2


def test_incorrect_target_source_hash_is_rejected(tmp_path: Path) -> None:
    provenance, callind = write_inputs(tmp_path, target_source_hash="0" * 64)
    with pytest.raises(ValueError, match="not linked to the supplied exact target evidence"):
        build_indirect_call_pointer_slots([provenance], [callind], program_id=PROGRAM)


def test_duplicate_callind_sites_are_rejected(tmp_path: Path) -> None:
    provenance, callind = write_inputs(tmp_path)
    callind.write_text(callind.read_text() * 2, encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate indirect-call site"):
        build_indirect_call_pointer_slots([provenance], [callind], program_id=PROGRAM)


def test_row_budget_applies_across_evidence_shards(tmp_path: Path) -> None:
    provenance, callind = write_inputs(tmp_path)
    second_callind = tmp_path / "callind-shard-2.jsonl"
    second_callind.write_text(callind.read_text(), encoding="utf-8")
    with pytest.raises(ValueError, match="combined indirect-call evidence row budget exceeded"):
        build_indirect_call_pointer_slots(
            [provenance], [callind, second_callind], program_id=PROGRAM, max_rows=1,
        )
