from __future__ import annotations

import csv
import hashlib
import io
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.benchmark import TOOLS
from revenginstr.state_machine import (
    CLAIM_SCOPE,
    FORMAT,
    LOAD_FORMAT,
    STORE_FORMAT,
    build_state_machine_candidates,
    main,
)

ROOT = Path(__file__).resolve().parents[1]
REPORT_SCHEMA = json.loads((ROOT / "schemas/state-machine-candidate-audit-v1.schema.json").read_text(encoding="utf-8"))
PCODE_HEADER = (
    "function_entry", "op_address", "op_time", "opcode", "output", "inputs",
    "callee_entry", "callee_name",
)
LOAD_HEADER = (
    "format", "function_entry", "function_name", "load_address", "load_time",
    "base_parameter_index", "field_offset", "address_pattern", "value_size",
    "value_token", "status",
)


def fixture():
    function_entry = "00401000"
    pcode_rows = [
        {
            "function_entry": function_entry, "op_address": "00401000", "op_time": "0", "opcode": "LOAD",
            "output": "def:00401000:0:4", "inputs": "const:ram:4;def:param0:4",
            "callee_entry": "-", "callee_name": "-",
        },
        {
            "function_entry": function_entry, "op_address": "00401004", "op_time": "1", "opcode": "INT_EQUAL",
            "output": "def:00401004:1:1", "inputs": "def:00401000:0:4;const:0x0:4",
            "callee_entry": "-", "callee_name": "-",
        },
        {
            "function_entry": function_entry, "op_address": "00401008", "op_time": "2", "opcode": "CBRANCH",
            "output": "-", "inputs": "const:00401020:4;def:00401004:1:1",
            "callee_entry": "-", "callee_name": "-",
        },
        {
            "function_entry": function_entry, "op_address": "00401010", "op_time": "3", "opcode": "STORE",
            "output": "-", "inputs": "const:ram:4;def:param0:4;const:0x1:1",
            "callee_entry": "-", "callee_name": "-",
        },
        {
            "function_entry": function_entry, "op_address": "00401014", "op_time": "4", "opcode": "RETURN",
            "output": "-", "inputs": "-", "callee_entry": "-", "callee_name": "-",
        },
        {
            "function_entry": function_entry, "op_address": "00401020", "op_time": "5", "opcode": "RETURN",
            "output": "-", "inputs": "-", "callee_entry": "-", "callee_name": "-",
        },
    ]

    def cfg_op(row: dict, *, memory: bool = False) -> dict:
        return {
            "address": row["op_address"], "time": int(row["op_time"]), "opcode": row["opcode"],
            "memory_space": "ram" if memory else None,
            "memory_width_bytes": 4 if memory else None,
            "memory_physical_space": "ram" if memory else None,
            "memory_pointer_width_bytes": 4 if memory else None,
        }

    cfg = {
        "format": "REVENGINSTR.GhidraFunctionPcodeCFG/3",
        "program_id": "analysis:fixture",
        "function_entry": function_entry,
        "entry_block_index": 0,
        "blocks": [
            {
                "block_index": 0, "start_address": "00401000", "stop_address": "00401008",
                "operations": [cfg_op(row, memory=row["opcode"] == "LOAD") for row in pcode_rows[:3]],
                "successors": [1, 2],
            },
            {
                "block_index": 1, "start_address": "00401010", "stop_address": "00401014",
                "operations": [cfg_op(pcode_rows[3], memory=True), cfg_op(pcode_rows[4])],
                "successors": [],
            },
            {
                "block_index": 2, "start_address": "00401020", "stop_address": "00401020",
                "operations": [cfg_op(pcode_rows[5])], "successors": [],
            },
        ],
    }
    parameter_load_rows = [{
        "format": LOAD_FORMAT, "function_entry": function_entry, "function_name": "opaque_fn",
        "load_address": "00401000", "load_time": "0", "base_parameter_index": "0",
        "field_offset": "0x4", "address_pattern": "param[0]+0x4", "value_size": "4",
        "value_token": "def:00401000:0:4", "status": "parameter_field_load",
    }]
    memory_store_rows = [{
        "format": STORE_FORMAT, "program_id": "analysis:fixture", "function_entry": function_entry,
        "address": "00401010", "time": 3, "opcode": "STORE", "memory_space": "ram",
        "memory_physical_space": "ram", "memory_width_bytes": 1, "memory_pointer_width_bytes": 4,
        "memory_space_size_bits": 32, "memory_addressable_unit_bytes": 1, "pointer_token": "def:param0:4",
        "root_parameter_index": 0, "offset_bytes": 4, "location_status": "parameter_rooted_constant_offset",
        "destination_pattern": "param[0]+0x4", "address_expression_ops": [],
    }]
    return cfg, pcode_rows, parameter_load_rows, memory_store_rows


def _build(cfg, pcode, loads, stores):
    return build_state_machine_candidates(
        [cfg], pcode, loads, stores,
        cfg_sha256="a" * 64, pcode_sha256="b" * 64,
        parameter_load_sha256="c" * 64, memory_store_sha256="d" * 64,
    )


def test_state_machine_candidate_requires_exact_compare_branch_and_same_field_write() -> None:
    cfg, pcode, loads, stores = fixture()

    report = _build(cfg, pcode, loads, stores)

    Draft202012Validator.check_schema(REPORT_SCHEMA)
    Draft202012Validator(REPORT_SCHEMA).validate(report)
    assert report["format"] == FORMAT
    assert report["claim_scope"] == CLAIM_SCOPE
    assert report["source"]["candidate_count"] == 1
    candidate = report["candidates"][0]
    assert candidate["field"] == {"root_parameter_index": 0, "offset_bytes": 4}
    assert candidate["branch"]["successor_block_indices"] == [1, 2]
    assert candidate["branch"]["write_reachable_successor_index"] == 1
    assert candidate["write"]["memory_store_record_index"] == 1
    assert "state_value" not in json.dumps(candidate)


def test_state_machine_accepts_parameter_load_exporter_token_alias() -> None:
    cfg, pcode, loads, stores = fixture()
    loads[0]["value_token"] = "def:LOAD@00401000:0:4"

    report = _build(cfg, pcode, loads, stores)

    assert report["source"]["parameter_load_rows"] == 1
    assert report["source"]["candidate_count"] == 1


@pytest.mark.parametrize("mutation", [
    "no_branch_dataflow", "compare_used_as_branch_target", "common_successor",
    "different_field", "load_after_compare",
])
def test_state_machine_candidates_omit_unjoined_or_nonselective_shapes(mutation: str) -> None:
    cfg, pcode, loads, stores = fixture()
    if mutation == "no_branch_dataflow":
        pcode[2]["inputs"] = "const:00401020:4;def:unrelated:1:1"
    elif mutation == "compare_used_as_branch_target":
        pcode[2]["inputs"] = "def:00401004:1:1;def:unrelated:1:1"
    elif mutation == "common_successor":
        cfg["blocks"][2]["successors"] = [1]
    elif mutation == "load_after_compare":
        cfg["blocks"][0]["operations"][:2] = reversed(cfg["blocks"][0]["operations"][:2])
    else:
        stores[0]["offset_bytes"] = 8

    report = _build(cfg, pcode, loads, stores)
    assert report["candidates"] == []


@pytest.mark.parametrize("mutation, message", [
    (lambda cfg, pcode, loads, stores: pcode.pop(), "operation populations differ"),
    (lambda cfg, pcode, loads, stores: stores.clear(), "sidecar and P-code STORE populations differ"),
    (lambda cfg, pcode, loads, stores: loads[0].update(value_token="def:wrong"), "does not join to the exact P-code LOAD output"),
])
def test_state_machine_candidates_fail_closed_on_broken_joins(mutation, message: str) -> None:
    cfg, pcode, loads, stores = fixture()
    mutation(cfg, pcode, loads, stores)
    with pytest.raises(ValueError, match=message):
        _build(cfg, pcode, loads, stores)


def _write_tsv(path: Path, header: tuple[str, ...], rows: list[dict]) -> None:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=header, delimiter="\t", lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    path.write_text(buffer.getvalue(), encoding="utf-8")


def test_state_machine_candidate_cli_pins_sources_and_writes_report(tmp_path: Path, capsys) -> None:
    assert TOOLS["state-machine-candidates"] == ("revenginstr.state_machine", "main")
    cfg, pcode, loads, stores = fixture()
    cfg_path = tmp_path / "cfg-v3.jsonl"
    pcode_path = tmp_path / "pcode-flow.tsv"
    load_path = tmp_path / "loads.tsv"
    store_path = tmp_path / "stores.jsonl"
    cfg_path.write_text(json.dumps(cfg) + "\n", encoding="utf-8")
    _write_tsv(pcode_path, PCODE_HEADER, pcode)
    _write_tsv(load_path, LOAD_HEADER, loads)
    store_path.write_text("".join(json.dumps(row) + "\n" for row in stores), encoding="utf-8")
    output = tmp_path / "nested" / "candidates.json"

    assert main([
        str(cfg_path), str(pcode_path), str(load_path), str(store_path), "--output", str(output)
    ]) == 0

    report = json.loads(output.read_text(encoding="utf-8"))
    Draft202012Validator(REPORT_SCHEMA).validate(report)
    assert report["source"]["cfg_sha256"] == hashlib.sha256(cfg_path.read_bytes()).hexdigest()
    assert "candidates: 1" in capsys.readouterr().out


def test_state_machine_candidate_budget_rejects_non_integer_values() -> None:
    cfg, pcode, loads, stores = fixture()
    with pytest.raises(ValueError, match="max_candidates must be positive"):
        build_state_machine_candidates(
            [cfg], pcode, loads, stores,
            cfg_sha256="a" * 64, pcode_sha256="b" * 64,
            parameter_load_sha256="c" * 64, memory_store_sha256="d" * 64,
            max_candidates=True,
        )
