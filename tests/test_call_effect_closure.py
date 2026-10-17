from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.receiver.call_effect_closure import (
    FORMAT,
    build_direct_call_memory_effect_closure,
    main,
)


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schemas/ghidra-direct-call-memory-effect-closure-v1.schema.json").read_text())
HEADER = "function_entry\top_address\top_time\topcode\toutput\tinputs\tcallee_entry\tcallee_name\n"


def flow(path: Path, entry: str, operations: list[tuple[str, str | None]]) -> Path:
    lines = [HEADER]
    for index, (opcode, target) in enumerate(operations, 1):
        address = f"{int(entry, 16) + index * 4:08x}"
        callee = target if opcode == "CALL" and target is not None else "-"
        name = f"FUN_{callee}" if callee != "-" else "-"
        lines.append(f"{entry}\t{address}\t{index}\t{opcode}\t-\t-\t{callee}\t{name}\n")
    path.write_text("".join(lines), encoding="utf-8")
    return path


def validate(rows: list[dict]) -> None:
    for row in rows:
        Draft202012Validator(SCHEMA).validate(row)


def test_nested_write_free_closure_pins_all_reachable_flows(tmp_path: Path) -> None:
    caller = flow(tmp_path / "caller.tsv", "00401000", [("CALL", "00402000")])
    first = flow(tmp_path / "first.tsv", "00402000", [("CALL", "00403000"), ("RETURN", None)])
    leaf = flow(tmp_path / "leaf.tsv", "00403000", [("LOAD", None), ("RETURN", None)])

    rows = build_direct_call_memory_effect_closure(
        "sample:program", caller, callee_flows=[("00402000", first), ("00403000", leaf)]
    )

    [row] = rows
    assert row["status"] == "no_explicit_memory_write"
    assert row["effect_opcodes"] == []
    assert row["provenance"]["closure_function_entries"] == ["00402000", "00403000"]
    assert row["provenance"]["closure_call_site_count"] == 1
    assert row["provenance"]["closure_sha256"] == sha256(
        json.dumps([
            {"function_entry": "00402000", "pcode_flow_sha256": sha256(first.read_bytes()).hexdigest(), "pcode_flow_record_count": 2},
            {"function_entry": "00403000", "pcode_flow_sha256": sha256(leaf.read_bytes()).hexdigest(), "pcode_flow_record_count": 2},
        ], sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    validate(rows)


def test_closed_write_free_cycle_terminates_by_function_identity(tmp_path: Path) -> None:
    caller = flow(tmp_path / "caller.tsv", "00401000", [("CALL", "00402000")])
    left = flow(tmp_path / "left.tsv", "00402000", [("CALL", "00403000"), ("RETURN", None)])
    right = flow(tmp_path / "right.tsv", "00403000", [("CALL", "00402000"), ("RETURN", None)])

    [row] = build_direct_call_memory_effect_closure(
        "p", caller, callee_flows=[("00402000", left), ("00403000", right)]
    )

    assert row["status"] == "no_explicit_memory_write"
    assert row["provenance"]["closure_function_entries"] == ["00402000", "00403000"]
    assert row["provenance"]["closure_call_site_count"] == 2
    validate([row])


@pytest.mark.parametrize(
    ("leaf_op", "expected_status", "expected_effect"),
    [
        ("STORE", "explicit_memory_write", "STORE"),
        ("CALLIND", "unknown_effect", "CALLIND"),
        ("UNIMPLEMENTED", "unknown_effect", "UNIMPLEMENTED"),
    ],
)
def test_nested_effects_remain_barriers(
    tmp_path: Path, leaf_op: str, expected_status: str, expected_effect: str,
) -> None:
    caller = flow(tmp_path / "caller.tsv", "00401000", [("CALL", "00402000")])
    first = flow(tmp_path / "first.tsv", "00402000", [("CALL", "00403000")])
    leaf = flow(tmp_path / "leaf.tsv", "00403000", [(leaf_op, None)])

    [row] = build_direct_call_memory_effect_closure(
        "p", caller, callee_flows=[("00402000", first), ("00403000", leaf)]
    )

    assert row["status"] == expected_status
    assert row["effect_opcodes"] == [expected_effect]
    validate([row])


def test_missing_nested_flow_is_unknown_and_missing_top_level_flow_stays_distinct(tmp_path: Path) -> None:
    caller = flow(tmp_path / "caller.tsv", "00401000", [
        ("CALL", "00402000"), ("CALL", "00404000"), ("CALLIND", None), ("CALL", None),
    ])
    first = flow(tmp_path / "first.tsv", "00402000", [("CALL", "00403000")])

    rows = build_direct_call_memory_effect_closure(
        "p", caller, callee_flows=[("00402000", first)]
    )

    assert [row["status"] for row in rows] == [
        "unknown_effect", "missing_callee_flow", "indirect_call", "unresolved_target",
    ]
    assert rows[0]["effect_opcodes"] == ["CALL"]
    assert rows[0]["provenance"]["closure_function_entries"] == ["00402000"]
    validate(rows)


def test_unused_flows_and_graph_budgets_fail_closed(tmp_path: Path) -> None:
    caller = flow(tmp_path / "caller.tsv", "00401000", [("CALL", "00402000")])
    callee = flow(tmp_path / "callee.tsv", "00402000", [("CALL", "00403000")])
    unused = flow(tmp_path / "unused.tsv", "00404000", [("RETURN", None)])
    with pytest.raises(ValueError, match="not reachable"):
        build_direct_call_memory_effect_closure(
            "p", caller, callee_flows=[("00402000", callee), ("00404000", unused)]
        )
    with pytest.raises(ValueError, match="function budget exceeded"):
        build_direct_call_memory_effect_closure(
            "p", caller, callee_flows=[("00402000", callee)], max_functions=1
        )
    with pytest.raises(ValueError, match="call memory effect budget exceeded"):
        build_direct_call_memory_effect_closure(
            "p", caller, callee_flows=[("00402000", callee)], max_calls=1
        )


def test_closure_visits_are_bounded_and_shared_targets_are_cached(tmp_path: Path) -> None:
    caller = flow(tmp_path / "caller.tsv", "00401000", [
        ("CALL", "00402000"), ("CALL", "00402000"),
    ])
    callee = flow(tmp_path / "callee.tsv", "00402000", [("CALL", "00403000")])
    leaf = flow(tmp_path / "leaf.tsv", "00403000", [("RETURN", None)])
    flows = [("00402000", callee), ("00403000", leaf)]

    rows = build_direct_call_memory_effect_closure(
        "p", caller, callee_flows=flows, max_closure_visits=6
    )
    assert [row["status"] for row in rows] == ["no_explicit_memory_write"] * 2
    with pytest.raises(ValueError, match="closure visit budget exceeded"):
        build_direct_call_memory_effect_closure(
            "p", caller, callee_flows=flows, max_closure_visits=5
        )


def test_closure_cli_writes_schema_valid_jsonl(tmp_path: Path, capsys) -> None:
    caller = flow(tmp_path / "caller.tsv", "00401000", [("CALL", "00402000")])
    callee = flow(tmp_path / "callee.tsv", "00402000", [("RETURN", None)])
    output = tmp_path / "out" / "closure.jsonl"

    assert main([
        str(caller), "--program-id", "sample:program",
        "--callee-flow", "00402000", str(callee), "--output", str(output),
    ]) == 0
    rows = [json.loads(line) for line in output.read_text().splitlines()]
    validate(rows)
    assert rows[0]["format"] == FORMAT
    assert "call sites: 1" in capsys.readouterr().out
