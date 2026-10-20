from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.indirect_call_target_triage_v2 import build_symbolic_indirect_call_target_triage


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schemas/indirect-call-target-triage-v2.schema.json").read_text())
SYMBOL_SCHEMA = json.loads((ROOT / "schemas/ghidra-indirect-call-symbol-candidates-v1.schema.json").read_text())
PROGRAM_SHA256 = "a" * 64


def ref(fmt: str, path: str, index: int = 1) -> dict:
    return {
        "source_format": fmt,
        "artifact_path": path,
        "artifact_sha256": "b" * 64,
        "record_index": index,
    }


def triage_row(address: str = "00401020") -> dict:
    alternative = {
        "root_kind": "unknown", "evidence_class": "derived_structural", "root_id": "def:00401020:1:4",
        "offset_bytes": None, "pointer_size_bytes": None, "address_space_token": None,
        "status": "call_barrier", "transformation_path": [], "evidence_refs": [],
    }
    return {
        "format": "REVENGINSTR.IndirectCallTargetTriage/1", "program_id": "sample:program",
        "program_sha256": PROGRAM_SHA256, "function_entry": "00401000", "call_address": address,
        "call_time": 4, "provenance_status": "unknown", "classification": "dynamic_barrier_only",
        "bounded_path_count": 0, "dynamic_barrier_count": 1, "limited_path_count": 0,
        "alternatives": [alternative], "static_target_candidate_scope": "none", "static_target_candidates": [],
        "pcode_operation": ref("REVENGINSTR.GhidraFunctionPcodeFlow/1", "flow.tsv"),
        "callind_evidence": ref("REVENGINSTR.GhidraIndirectCallEvidence/4", "callind.jsonl"),
        "source": ref("REVENGINSTR.PointerProvenance/1", "provenance.jsonl"),
    }


def candidate_row(address: str = "00401020") -> dict:
    return {
        "format": "REVENGINSTR.GhidraIndirectCallSymbolCandidates/1", "program_id": "sample:program",
        "program_sha256": PROGRAM_SHA256, "function_entry": "00401000", "call_address": address,
        "call_time": 4, "candidates": [{
            "candidate_kind": "external_api", "module": "KERNEL32.DLL", "symbol": "ExampleApi",
            "address": None, "alternative_indexes": [1],
            "evidence_refs": [ref("REVENGINSTR.GhidraFunctionInstructions/1", "instructions.jsonl")],
            "limitations": ["runtime_address_unresolved", "runtime_selection_unresolved"],
        }],
    }


def write_jsonl(path: Path, rows: list[dict]) -> Path:
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")
    return path


def test_symbolic_targets_join_exact_sites_and_preserve_v1(tmp_path: Path) -> None:
    triage = triage_row()
    Draft202012Validator(SYMBOL_SCHEMA).validate(candidate_row())
    triage_path = write_jsonl(tmp_path / "triage.jsonl", [triage])
    candidate_path = write_jsonl(tmp_path / "symbols.jsonl", [candidate_row()])

    [row] = build_symbolic_indirect_call_target_triage(triage_path, [candidate_path])

    assert row["format"] == "REVENGINSTR.IndirectCallTargetTriage/2"
    assert {key: row[key] for key in triage} == {**triage, "format": row["format"]}
    assert row["symbolic_target_candidates"][0]["alternative_indexes"] == [1]
    assert row["symbolic_target_candidates"][0]["address"] is None
    assert row["symbolic_target_source"] == {
        "source_format": "REVENGINSTR.GhidraIndirectCallSymbolCandidates/1",
        "artifact_path": str(candidate_path), "artifact_sha256": sha256(candidate_path.read_bytes()).hexdigest(),
        "record_index": 1,
    }
    Draft202012Validator(SCHEMA).validate(row)


def test_unmatched_callsite_and_out_of_range_alternative_fail_closed(tmp_path: Path) -> None:
    triage_path = write_jsonl(tmp_path / "triage.jsonl", [triage_row()])
    candidate_path = write_jsonl(tmp_path / "symbols.jsonl", [candidate_row("00401024")])
    with pytest.raises(ValueError, match="no exact CALLIND triage site match"):
        build_symbolic_indirect_call_target_triage(triage_path, [candidate_path])

    symbols = candidate_row()
    symbols["candidates"][0]["candidate_kind"] = ["external_api"]
    write_jsonl(candidate_path, [symbols])
    with pytest.raises(ValueError, match="unsupported candidate_kind"):
        build_symbolic_indirect_call_target_triage(triage_path, [candidate_path])

    symbols = candidate_row()
    symbols["candidates"][0]["alternative_indexes"] = [2]
    write_jsonl(candidate_path, [symbols])
    with pytest.raises(ValueError, match="invalid alternative_indexes"):
        build_symbolic_indirect_call_target_triage(triage_path, [candidate_path])


def test_retained_shift_replay_rebuilds_exact_symbolic_rows(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(ROOT)
    replay = Path("docs/evidence/receiver-field-access/nfs-shift-screening-20261019/scan37/replay-0041dd40")
    output = replay / "callind-target-triage-v2.jsonl"
    rebuilt = build_symbolic_indirect_call_target_triage(
        replay / "callind-target-triage.jsonl", [replay / "callind-symbol-candidates.jsonl"],
    )
    retained = [json.loads(line) for line in output.read_text(encoding="utf-8").splitlines()]

    assert rebuilt == retained
    annotated = {
        (row["function_entry"], row["call_address"]): [
            (candidate["module"], candidate["symbol"], candidate["alternative_indexes"])
            for candidate in row["symbolic_target_candidates"]
        ]
        for row in rebuilt if row["symbolic_target_candidates"]
    }
    assert annotated == {
        ("0090aa27", "0090aa89"): [("KERNEL32.DLL", "EncodePointer", [2])],
        ("0090aa9e", "0090ab00"): [("KERNEL32.DLL", "DecodePointer", [2])],
        ("009189cd", "00918a4c"): [
            ("KERNEL32.DLL", "InitializeCriticalSectionAndSpinCount", [2, 3]),
            ("SHIFT.exe", "___crtInitCritSecNoSpinCount@8", [1, 2]),
        ],
    }
    assert len(rebuilt) == 22
    assert all(row["classification"] == "mixed_bounded_and_blocked" for row in rebuilt if row["symbolic_target_candidates"])
    for row in rebuilt:
        Draft202012Validator(SCHEMA).validate(row)
