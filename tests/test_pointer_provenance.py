from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.pointer_provenance import (
    FORMAT,
    FLOW_HEADER,
    ROOT_HEADER_V2,
    build_pointer_provenance,
)

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas/pointer-provenance-v1.schema.json"
FUNCTION = "00401000"
CALLEE = "00402000"


def flow_row(address: str, time: int, opcode: str, output: str, inputs: str, callee: str = "-") -> dict[str, str]:
    return {
        "function_entry": FUNCTION,
        "op_address": address,
        "op_time": str(time),
        "opcode": opcode,
        "output": output,
        "inputs": inputs,
        "callee_entry": callee,
        "callee_name": "-",
    }


def root_row(
    parameter: int,
    caller_parameter: int,
    *,
    call_site: str = "00401040",
    offset: str = "0x0",
) -> dict[str, str]:
    return {
        "format": "REVENGINSTR.GhidraCallerArgumentParameterRoot/2",
        "plan_id": "synthetic-plan",
        "callee_entry": CALLEE,
        "parameter_index": str(parameter),
        "caller_entry": FUNCTION,
        "caller_call_site": call_site,
        "caller_parameter_index": str(caller_parameter),
        "caller_parameter_offset_bytes": offset,
        "argument_node_id": "0",
        "status": "constant_offset_parameter_root",
    }


def write_tsv(path: Path, header: tuple[str, ...], rows: list[dict[str, str]]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=header, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def analyze(
    tmp_path: Path,
    rows: list[dict[str, str]],
    roots: list[dict[str, str]] | None = None,
    callind_rows: list[dict] | None = None,
    **kwargs,
):
    flow_path = tmp_path / "flow.tsv"
    write_tsv(flow_path, FLOW_HEADER, rows)
    root_path = None
    if roots is not None:
        root_path = tmp_path / "roots.tsv"
        write_tsv(root_path, ROOT_HEADER_V2, roots)
    callind_path = None
    if callind_rows is not None:
        callind_path = tmp_path / "callind.jsonl"
        callind_path.write_text("".join(json.dumps(row) + "\n" for row in callind_rows), encoding="utf-8")
    return build_pointer_provenance(
        [flow_path], program_id="synthetic:1", parameter_roots_tsv=root_path,
        callind_evidence_paths=[] if callind_path is None else [callind_path], **kwargs,
    )


def record_at(rows: list[dict], address: str) -> dict:
    return next(row for row in rows if row["operation_address"] == address)


def test_constant_pointer_offsets_keep_exact_root_and_evidence(tmp_path: Path) -> None:
    rows = analyze(tmp_path, [
        flow_row("00401020", 7, "PTRADD", "def:00401020:7:4", "register:0010:4;const:0x2:4;const:0x4:4"),
        flow_row("00401024", 8, "PTRSUB", "def:00401024:8:4", "register:0010:4;const:0x4:4"),
        flow_row("00401028", 9, "INT_ADD", "def:00401028:9:4", "register:0010:4;const:0x8:4"),
        flow_row("00401032", 10, "INT_ADD", "def:00401032:10:4", "const:0x4:4;register:0010:4"),
        flow_row("00401036", 11, "INT_SUB", "def:00401036:11:4", "register:0010:4;const:0x4:4"),
        flow_row("00401040", 12, "CALL", "-", "register:0010:4", CALLEE),
    ], [root_row(0, 1, offset="0x10")])

    positive = record_at(rows, "00401020")
    negative = record_at(rows, "00401024")
    assert positive["format"] == FORMAT
    assert positive["status"] == negative["status"] == "resolved"
    assert positive["alternatives"][0]["root_id"] == "parameter:1"
    assert positive["alternatives"][0]["offset_bytes"] == 24
    assert negative["alternatives"][0]["offset_bytes"] == 12
    assert record_at(rows, "00401028")["alternatives"][0]["offset_bytes"] == 24
    assert record_at(rows, "00401032")["alternatives"][0]["offset_bytes"] == 20
    assert record_at(rows, "00401036")["alternatives"][0]["offset_bytes"] == 12
    assert {ref["source_format"] for ref in positive["alternatives"][0]["evidence_refs"]} == {
        "REVENGINSTR.GhidraCallerArgumentParameterRoot/2",
        "REVENGINSTR.GhidraFunctionPcodeFlow/1",
    }


def test_phi_preserves_distinct_formal_roots_as_alternatives(tmp_path: Path) -> None:
    rows = analyze(tmp_path, [
        flow_row("00401020", 7, "MULTIEQUAL", "def:00401020:7:4", "register:0010:4;register:0020:4"),
        flow_row("00401040", 9, "CALL", "-", "register:0010:4;register:0020:4", CALLEE),
    ], [root_row(0, 0), root_row(1, 1)])

    phi = record_at(rows, "00401020")
    assert phi["status"] == "ambiguous"
    assert {item["root_id"] for item in phi["alternatives"]} == {"parameter:0", "parameter:1"}


def test_phi_alternative_budget_fails_closed(tmp_path: Path) -> None:
    rows = analyze(tmp_path, [
        flow_row("00401020", 7, "MULTIEQUAL", "def:00401020:7:4", "register:0010:4;register:0020:4"),
        flow_row("00401040", 9, "CALL", "-", "register:0010:4;register:0020:4", CALLEE),
    ], [root_row(0, 0), root_row(1, 1)], max_alternatives=1)
    phi = record_at(rows, "00401020")
    assert phi["status"] == "alternative_limit"
    assert phi["alternatives"][0]["offset_bytes"] is None


def test_dynamic_index_does_not_become_a_constant_offset(tmp_path: Path) -> None:
    rows = analyze(tmp_path, [
        flow_row("00401010", 6, "COPY", "def:00401010:6:4", "register:0030:4"),
        flow_row("00401020", 7, "PTRADD", "def:00401020:7:4", "register:0010:4;def:00401010:6:4;const:0x4:4"),
        flow_row("00401040", 9, "CALL", "-", "register:0010:4", CALLEE),
    ], [root_row(0, 0)])
    pointer = record_at(rows, "00401020")
    assert pointer["status"] == "dynamic_offset"
    assert pointer["alternatives"][0]["offset_bytes"] is None


def test_negative_ptradd_index_is_signed(tmp_path: Path) -> None:
    rows = analyze(tmp_path, [
        flow_row("00401020", 7, "PTRADD", "def:00401020:7:4", "register:0010:4;const:0xffffffff:4;const:0x4:4"),
        flow_row("00401040", 9, "CALL", "-", "register:0010:4", CALLEE),
    ], [root_row(0, 0)])
    assert record_at(rows, "00401020")["alternatives"][0]["offset_bytes"] == -4


def test_cycle_overflow_and_width_mismatch_abstain(tmp_path: Path) -> None:
    rows = analyze(tmp_path, [
        flow_row("00401010", 6, "COPY", "def:00401010:6:4", "def:00401010:6:4"),
        flow_row("00401020", 7, "PTRADD", "def:00401020:7:4", "register:0010:4;const:0x1:4;const:0x1:4"),
        flow_row("00401024", 8, "PTRADD", "def:00401024:8:8", "register:0010:4;const:0x1:4;const:0x1:4"),
        flow_row("00401040", 9, "CALL", "-", "register:0010:4", CALLEE),
    ], [root_row(0, 0, offset="0x7fffffff")])
    assert record_at(rows, "00401010")["status"] == "cycle"
    assert record_at(rows, "00401020")["status"] == "offset_overflow"
    assert record_at(rows, "00401024")["status"] == "width_mismatch"


def test_unrooted_register_load_anchor_and_indirect_barrier(tmp_path: Path) -> None:
    rows = analyze(tmp_path, [
        flow_row("00401010", 6, "COPY", "def:00401010:6:4", "register:0030:4"),
        flow_row("00401020", 7, "LOAD", "def:00401020:7:4", "const:0x1:4;register:0030:4"),
        flow_row("00401024", 8, "PTRADD", "def:00401024:8:4", "def:00401020:7:4;const:0x2:4;const:0x4:4"),
        flow_row("00401030", 9, "INDIRECT", "def:00401030:9:4", "register:0030:4"),
    ])
    assert record_at(rows, "00401010")["status"] == "unknown"
    load = record_at(rows, "00401020")
    assert load["status"] == "load_anchor"
    assert load["alternatives"][0]["root_kind"] == "memory_read_anchor"
    assert load["load_address"]["status"] == "unknown"
    derived = record_at(rows, "00401024")
    assert derived["status"] == "resolved"
    assert derived["alternatives"][0]["root_kind"] == "memory_read_anchor"
    assert derived["alternatives"][0]["offset_bytes"] == 8
    assert record_at(rows, "00401030")["status"] == "indirect_barrier"


def test_caller_root_requires_an_exact_callsite_match(tmp_path: Path) -> None:
    flow_path = tmp_path / "flow.tsv"
    root_path = tmp_path / "roots.tsv"
    write_tsv(flow_path, FLOW_HEADER, [flow_row("00401040", 9, "CALL", "-", "register:0010:4", CALLEE)])
    write_tsv(root_path, ROOT_HEADER_V2, [root_row(0, 0, call_site="00401044")])
    with pytest.raises(ValueError, match="one exact P-code CALL"):
        build_pointer_provenance([flow_path], program_id="synthetic:1", parameter_roots_tsv=root_path)


def test_depth_budget_is_visible(tmp_path: Path) -> None:
    rows = analyze(tmp_path, [
        flow_row("00401010", 6, "COPY", "def:00401010:6:4", "register:0010:4"),
        flow_row("00401020", 7, "COPY", "def:00401020:7:4", "def:00401010:6:4"),
        flow_row("00401030", 8, "COPY", "def:00401030:8:4", "def:00401020:7:4"),
    ], max_depth=1)
    assert record_at(rows, "00401030")["status"] == "depth_limit"


def test_output_satisfies_schema_and_load_address_keeps_context(tmp_path: Path) -> None:
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    rows = analyze(tmp_path, [
        flow_row("00401020", 7, "LOAD", "def:00401020:7:8", "const:0x1:4;const:0x401000:8"),
    ])
    Draft202012Validator(schema).validate(rows[0])
    assert rows[0]["load_address"]["address_token"] == "const:0x401000:8"
    assert rows[0]["load_address"]["alternatives"][0]["root_kind"] == "address_anchor"


def test_callind_target_joins_exact_site_and_definition(tmp_path: Path) -> None:
    rows = analyze(tmp_path, [
        flow_row("00401020", 7, "PTRADD", "def:00401020:7:4", "const:0x401000:4;const:0x1:4;const:0x4:4"),
        flow_row("00401040", 8, "CALLIND", "-", "-"),
    ], callind_rows=[{
        "format": "REVENGINSTR.GhidraIndirectCallEvidence/1",
        "program": "synthetic",
        "requested": FUNCTION,
        "function_entry": FUNCTION,
        "call_address": "00401040",
        "call_time": 8,
        "target": "def:PTRADD@00401020:7:4",
        "target_expression": "PTRADD(const:0x401000:4,const:0x1:4,const:0x4:4)",
        "arg_count": 0,
    }])
    target = next(row for row in rows if row["record_kind"] == "callind_target")
    Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))).validate(target)
    assert target["operation_address"] == "00401040"
    assert target["status"] == "resolved"
    assert target["output_token"] == "def:00401020:7:4"
    assert target["alternatives"][0]["root_kind"] == "address_anchor"
    assert target["alternatives"][0]["offset_bytes"] == 4
    assert target["target_source"]["source_format"] == "REVENGINSTR.GhidraIndirectCallEvidence/1"


def test_callind_v2_evidence_keeps_executable_identity_source(tmp_path: Path) -> None:
    rows = analyze(tmp_path, [flow_row("00401040", 8, "CALLIND", "-", "-")], callind_rows=[{
        "format": "REVENGINSTR.GhidraIndirectCallEvidence/2",
        "program": "synthetic.exe",
        "program_sha256": "a" * 64,
        "architecture": {"language_id": "x86:LE:32:default", "pointer_width_bytes": 4, "endianness": "little"},
        "requested": FUNCTION,
        "function_entry": FUNCTION,
        "call_address": "00401040",
        "call_time": 8,
        "target": "const:0x401234:4",
        "target_expression": "const:0x401234:4",
        "arg_count": 0,
    }])
    target = next(row for row in rows if row["record_kind"] == "callind_target")
    assert target["target_source"]["source_format"] == "REVENGINSTR.GhidraIndirectCallEvidence/2"


def test_callind_evidence_must_match_an_exact_call_site(tmp_path: Path) -> None:
    callind = {
        "format": "REVENGINSTR.GhidraIndirectCallEvidence/1",
        "program": "synthetic",
        "requested": FUNCTION,
        "function_entry": FUNCTION,
        "call_address": "00401040",
        "call_time": 99,
        "target": "register:0010:4",
        "target_expression": "register:0010:4",
        "arg_count": 0,
    }
    with pytest.raises(ValueError, match="no exact CALLIND"):
        analyze(tmp_path, [flow_row("00401040", 8, "CALLIND", "-", "-")], callind_rows=[callind])


def test_constant_callind_target_remains_an_address_anchor(tmp_path: Path) -> None:
    rows = analyze(tmp_path, [flow_row("00401040", 8, "CALLIND", "-", "-")], callind_rows=[{
        "format": "REVENGINSTR.GhidraIndirectCallEvidence/1",
        "program": "synthetic",
        "requested": FUNCTION,
        "function_entry": FUNCTION,
        "call_address": "00401040",
        "call_time": 8,
        "target": "const:0x401234:4",
        "target_expression": "const:0x401234:4",
        "arg_count": 0,
    }])
    target = next(row for row in rows if row["record_kind"] == "callind_target")
    assert target["status"] == "resolved"
    assert target["alternatives"][0]["root_kind"] == "address_anchor"
