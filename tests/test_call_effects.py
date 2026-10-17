from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.benchmark import run_benchmark
from revenginstr.receiver.call_effects import FORMAT, build_direct_call_memory_effects, main


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = json.loads((ROOT / "schemas/ghidra-direct-call-memory-effect-v1.schema.json").read_text())
HEADER = "function_entry\top_address\top_time\topcode\toutput\tinputs\tcallee_entry\tcallee_name\n"


def flow(path: Path, records: list[tuple[str, str, str, str]]) -> Path:
    rows = [HEADER]
    for entry, address, time, opcode in records:
        callee = "00402000" if opcode == "CALL" else "-"
        name = "helper" if callee != "-" else "-"
        rows.append(f"{entry}\t{address}\t{time}\t{opcode}\t-\t-\t{callee}\t{name}\n")
    path.write_text("".join(rows), encoding="utf-8")
    return path


def test_direct_call_memory_effects_mark_only_closed_pure_callee_write_free(tmp_path: Path) -> None:
    caller = flow(tmp_path / "caller.tsv", [
        ("00401000", "00401020", "7", "CALL"),
        ("00401000", "00401024", "8", "CALLIND"),
    ])
    callee = flow(tmp_path / "callee.tsv", [
        ("00402000", "00402010", "1", "LOAD"),
        ("00402000", "00402014", "2", "INT_ADD"),
        ("00402000", "00402018", "3", "RETURN"),
    ])

    rows = build_direct_call_memory_effects(
        "consumer:program", caller, callee_flows=[("00402000", callee)]
    )
    assert [row["status"] for row in rows] == ["no_explicit_memory_write", "indirect_call"]
    assert rows[0]["provenance"]["caller_pcode_flow_sha256"] == sha256(caller.read_bytes()).hexdigest()
    assert rows[0]["provenance"]["callee_pcode_flow_sha256"] == sha256(callee.read_bytes()).hexdigest()
    assert rows[1]["callee_entry"] is None
    for row in rows:
        Draft202012Validator(SCHEMA).validate(row)


@pytest.mark.parametrize(
    ("opcodes", "expected_status", "expected_effects"),
    [
        (["STORE", "RETURN"], "explicit_memory_write", ["STORE"]),
        (["CALL", "RETURN"], "unknown_effect", ["CALL"]),
        (["CALLOTHER"], "unknown_effect", ["CALLOTHER"]),
        (["UNIMPLEMENTED"], "unknown_effect", ["UNIMPLEMENTED"]),
    ],
)
def test_direct_call_memory_effects_fail_closed_for_writes_and_unmodeled_ops(
    tmp_path: Path, opcodes: list[str], expected_status: str, expected_effects: list[str],
) -> None:
    caller = flow(tmp_path / "caller.tsv", [("00401000", "00401020", "7", "CALL")])
    callee = flow(tmp_path / "callee.tsv", [
        ("00402000", f"004020{index:x}", str(index), opcode)
        for index, opcode in enumerate(opcodes, 1)
    ])

    [row] = build_direct_call_memory_effects(
        "p", caller, callee_flows=[("00402000", callee)]
    )
    assert row["status"] == expected_status
    assert row["effect_opcodes"] == expected_effects
    Draft202012Validator(SCHEMA).validate(row)


def test_direct_call_memory_effects_keep_unresolved_and_missing_calls_unknown(tmp_path: Path) -> None:
    caller = tmp_path / "caller.tsv"
    caller.write_text(
        HEADER
        + "00401000\t00401020\t7\tCALL\t-\t-\t-\t-\n"
        + "00401000\t00401024\t8\tCALL\t-\t-\t00402000\thelper\n",
        encoding="utf-8",
    )
    rows = build_direct_call_memory_effects("p", caller)
    assert [row["status"] for row in rows] == ["unresolved_target", "missing_callee_flow"]
    for row in rows:
        Draft202012Validator(SCHEMA).validate(row)


def test_direct_call_memory_effects_reject_invalid_or_unused_callee_flows(tmp_path: Path) -> None:
    caller = flow(tmp_path / "caller.tsv", [("00401000", "00401020", "7", "CALL")])
    wrong_callee = flow(tmp_path / "wrong.tsv", [("00403000", "00403010", "1", "RETURN")])
    with pytest.raises(ValueError, match="expected P-code flow for callee"):
        build_direct_call_memory_effects("p", caller, callee_flows=[("00402000", wrong_callee)])
    with pytest.raises(ValueError, match="max_calls must be positive"):
        build_direct_call_memory_effects("p", caller, max_calls=0)
    with pytest.raises(ValueError, match="P-code flow byte budget exceeded"):
        build_direct_call_memory_effects("p", caller, max_flow_bytes=1)
    with pytest.raises(ValueError, match="P-code flow operation budget exceeded"):
        build_direct_call_memory_effects("p", caller, callee_flows=[("00402000", flow(
            tmp_path / "callee.tsv", [("00402000", "00402010", "1", "RETURN")],
        ))], max_flow_operations=1)


def test_direct_call_memory_effects_cli_writes_jsonl(tmp_path: Path, capsys) -> None:
    caller = flow(tmp_path / "caller.tsv", [("00401000", "00401020", "7", "CALL")])
    callee = flow(tmp_path / "callee.tsv", [("00402000", "00402010", "1", "RETURN")])
    output = tmp_path / "nested" / "effects.jsonl"
    assert main([
        str(caller), "--program-id", "consumer:program",
        "--callee-flow", "00402000", str(callee), "--output", str(output),
    ]) == 0
    [row] = [json.loads(line) for line in output.read_text().splitlines()]
    Draft202012Validator(SCHEMA).validate(row)
    assert row["format"] == FORMAT
    assert "call sites: 1" in capsys.readouterr().out


def test_direct_call_memory_effects_can_run_as_frozen_benchmark_stage(tmp_path: Path) -> None:
    caller = flow(tmp_path / "caller.tsv", [("00401000", "00401020", "7", "CALL")])
    callee = flow(tmp_path / "callee.tsv", [("00402000", "00402010", "1", "RETURN")])
    pcode_schema = ROOT / "schemas/ghidra-function-pcode-flow-v1.schema.json"
    output_schema = ROOT / "schemas/ghidra-direct-call-memory-effect-v1.schema.json"

    def contract(path: Path, version: str) -> dict[str, str]:
        return {"path": str(path), "version": version, "sha256": sha256(path.read_bytes()).hexdigest()}

    def artifact(path: Path, *, role: str, content: str, format: str | None, schema: str | None = None) -> dict:
        record = {"path": path.name, "role": role, "kind": "file", "content": content}
        if format is not None:
            record["format"] = format
        if schema is not None:
            record["schema"] = schema
        if role == "input":
            record["sha256"] = sha256(path.read_bytes()).hexdigest()
        return record

    output = tmp_path / "direct-call-effects.jsonl"
    manifest = {
        "format": "REVENGINSTR.BenchmarkManifest/1",
        "benchmark": {
            "id": "synthetic-direct-call-effects", "dataset_id": "synthetic-pcode",
            "dataset_artifact": "caller_flow", "split_id": "synthetic", "family_set_id": None,
        },
        "toolchain": {"revenginstr_version": "0.5.2"},
        "schemas": {
            "pcode_flow": contract(pcode_schema, "REVENGINSTR.GhidraFunctionPcodeFlow/1 TSV row"),
            "call_effect": contract(output_schema, "REVENGINSTR.GhidraDirectCallMemoryEffect/1 JSONL row"),
        },
        "artifacts": {
            "caller_flow": artifact(caller, role="input", content="tsv", format=None, schema="pcode_flow"),
            "callee_flow": artifact(callee, role="input", content="tsv", format=None, schema="pcode_flow"),
            "call_effects": artifact(output, role="output", content="jsonl", format="REVENGINSTR.GhidraDirectCallMemoryEffect/1", schema="call_effect"),
        },
        "configs": {},
        "stages": [{
            "id": "build_direct_call_effects", "tool": "direct-call-memory-effects",
            "args": [
                "${artifact:caller_flow}", "--program-id", "synthetic:program",
                "--callee-flow", "00402000", "${artifact:callee_flow}",
                "--output", "${artifact:call_effects}",
            ],
            "inputs": ["caller_flow", "callee_flow"], "outputs": ["call_effects"],
        }],
    }
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    summary, code = run_benchmark(manifest_path, mode="smoke", output_path=tmp_path / "summary.json")
    assert code == 0
    assert summary["status"] == "passed"
