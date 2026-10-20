from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from pathlib import Path

from jsonschema import Draft202012Validator

from revenginstr.direct_call_argument_definitions import (
    CALL_FORMAT,
    PCODE_FORMAT,
    _jsonl,
    resolve_call_argument_definitions,
)
from revenginstr.direct_call_argument_traces import trace_call_argument_operands

ROOT = Path(__file__).resolve().parents[1]
REPLAY = ROOT / (
    "docs/evidence/semantic-program-graph-v4/"
    "nevergone-runtime-call-arguments-20261020"
)
RUNTIME = ROOT / "docs/evidence/runtime-static-correlation-v1/nevergone-device-runtime-20261019"
FLOW_PATHS = [
    RUNTIME / "LoadGameLevels.pcode-flow.tsv",
    RUNTIME / "CCFileUtilsAndroid-getFileData.pcode-flow.tsv",
]
FLOW_COLUMNS = [
    "function_entry", "op_address", "op_time", "opcode", "output", "inputs",
    "callee_entry", "callee_name",
]
PROGRAM_SHA256 = "a" * 64


def _fixture(
    tmp_path: Path,
    producer_rows: list[dict[str, str]],
    argument_token: str,
    *,
    max_depth: int = 64,
    max_nodes_per_argument: int = 4096,
) -> dict:
    tmp_path.mkdir(parents=True, exist_ok=True)
    call_row = {
        "function_entry": "1000",
        "op_address": "1002",
        "op_time": "3",
        "opcode": "CALL",
        "output": "-",
        "inputs": argument_token,
        "callee_entry": "2000",
        "callee_name": "fixture_callee",
    }
    rows = [*producer_rows, call_row]
    path = tmp_path / "flow.tsv"
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=FLOW_COLUMNS, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    pcode_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
    observation = {
        "format": CALL_FORMAT,
        "program_id": "fixture-program",
        "program_sha256": PROGRAM_SHA256,
        "caller_entry": "1000",
        "callee_entry": "2000",
        "call_address": "1002",
        "call_time": 3,
        "argument_count": 1,
        "arguments": [{"index": 0, "value_token": argument_token, "width_bytes": 4}],
        "evidence_ref": {
            "artifact_sha256": pcode_sha256,
            "record_index": len(rows),
            "source_format": PCODE_FORMAT,
        },
    }
    observation_path = tmp_path / "call-arguments.jsonl"
    observation_path.write_text(json.dumps(observation, sort_keys=True) + "\n", encoding="utf-8")
    observations, observations_sha256 = _jsonl(observation_path)
    definitions = resolve_call_argument_definitions(
        observations,
        observations_sha256=observations_sha256,
        pcode_paths=[path],
    )
    definitions_path = tmp_path / "definitions.jsonl"
    definitions_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in definitions),
        encoding="utf-8",
    )
    definitions_sha256 = hashlib.sha256(definitions_path.read_bytes()).hexdigest()
    return trace_call_argument_operands(
        observations,
        observations_sha256=observations_sha256,
        definition_rows=definitions,
        definitions_sha256=definitions_sha256,
        pcode_paths=[path],
        max_depth=max_depth,
        max_nodes_per_argument=max_nodes_per_argument,
    )[0]


def _row(address: str, time: str, opcode: str, output: str, inputs: str) -> dict[str, str]:
    return {
        "function_entry": "1000",
        "op_address": address,
        "op_time": time,
        "opcode": opcode,
        "output": output,
        "inputs": inputs,
        "callee_entry": "-",
        "callee_name": "-",
    }


def test_nevergone_operand_traces_are_deterministic_and_hash_pinned() -> None:
    observations_path = REPLAY / "call-arguments.jsonl"
    definitions_path = REPLAY / "argument-definitions.jsonl"
    output_path = REPLAY / "argument-operand-traces.jsonl"
    observations, observations_sha256 = _jsonl(observations_path)
    definitions, definitions_sha256 = _jsonl(definitions_path)
    rows = [json.loads(line) for line in output_path.read_text(encoding="utf-8").splitlines()]
    rebuilt = trace_call_argument_operands(
        observations,
        observations_sha256=observations_sha256,
        definition_rows=definitions,
        definitions_sha256=definitions_sha256,
        pcode_paths=FLOW_PATHS,
    )
    rebuilt_bytes = "".join(json.dumps(row, sort_keys=True) + "\n" for row in rebuilt).encode()
    assert rebuilt_bytes == output_path.read_bytes()

    schema = json.loads(
        (ROOT / "schemas/direct-call-argument-operand-trace-v1.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    for row in rows:
        validator.validate(row)

    states = Counter(row["trace_state"] for row in rows)
    assert len(rows) == 70
    assert states == {"closed": 28, "boundary_reached": 28, "non_definition_token": 14}
    assert sum(len(row["nodes"]) for row in rows) == 87
    assert sum(len(row["operand_edges"]) for row in rows) == 33
    assert sum(len(row["boundary_rows"]) for row in rows) == 34
    pcode_hashes = {hashlib.sha256(path.read_bytes()).hexdigest() for path in FLOW_PATHS}
    for row in rows:
        assert row["call_pcode_evidence_ref"]["artifact_sha256"] in pcode_hashes
        assert all(node["evidence_ref"]["artifact_sha256"] == row["call_pcode_evidence_ref"]["artifact_sha256"] for node in row["nodes"])


def test_operand_trace_preserves_cycles_and_internal_ambiguity(tmp_path: Path) -> None:
    root_ambiguous_trace = _fixture(
        tmp_path / "root-ambiguous",
        [
            _row("1000", "1", "COPY", "def:1000:1:4", "const:0x1:4"),
            _row("1000", "1", "COPY", "def:1000:1:4", "register:register:00000001:4"),
        ],
        "def:1000:1:4",
    )
    assert root_ambiguous_trace["trace_state"] == "ambiguous_definition"
    assert len(root_ambiguous_trace["root_definition_refs"]) == 2
    assert root_ambiguous_trace["nodes"] == []

    cycle_trace = _fixture(
        tmp_path / "cycle",
        [
            _row("1000", "1", "MULTIEQUAL", "def:1000:1:4", "def:1001:2:4"),
            _row("1001", "2", "COPY", "def:1001:2:4", "def:1000:1:4"),
        ],
        "def:1000:1:4",
    )
    assert cycle_trace["trace_state"] == "cycle_present"
    assert len(cycle_trace["cycle_edges"]) == 1

    ambiguous_trace = _fixture(
        tmp_path / "ambiguous",
        [
            _row("1000", "1", "COPY", "def:1000:1:4", "def:1001:2:4"),
            _row("1001", "2", "COPY", "def:1001:2:4", "const:0x1:4"),
            _row("1001", "2", "COPY", "def:1001:2:4", "register:register:00000001:4"),
        ],
        "def:1000:1:4",
    )
    assert ambiguous_trace["trace_state"] == "partial"
    assert ambiguous_trace["unresolved_operands"][0]["resolution_state"] == "ambiguous_definition"
    assert len(ambiguous_trace["unresolved_operands"][0]["candidate_refs"]) == 2


def test_operand_trace_marks_missing_and_resource_limits(tmp_path: Path) -> None:
    missing_trace = _fixture(
        tmp_path / "missing",
        [_row("1000", "1", "COPY", "def:1000:1:4", "def:1009:9:4")],
        "def:1000:1:4",
    )
    assert missing_trace["trace_state"] == "partial"
    assert missing_trace["unresolved_operands"][0]["resolution_state"] == "definition_not_found"

    chain = [
        _row("1000", "1", "COPY", "def:1000:1:4", "def:1001:2:4"),
        _row("1001", "2", "COPY", "def:1001:2:4", "const:0x1:4"),
    ]
    depth_trace = _fixture(
        tmp_path / "depth", chain, "def:1000:1:4", max_depth=1,
    )
    assert depth_trace["trace_state"] == "depth_limit"
    assert depth_trace["unresolved_operands"][0]["resolution_state"] == "depth_limit"

    node_trace = _fixture(
        tmp_path / "nodes", chain, "def:1000:1:4", max_nodes_per_argument=1,
    )
    assert node_trace["trace_state"] == "node_limit"
    assert node_trace["unresolved_operands"][0]["resolution_state"] == "node_limit"


def test_non_definition_argument_has_no_trace_nodes(tmp_path: Path) -> None:
    trace = _fixture(tmp_path / "constant", [], "const:0x1:4")
    assert trace["definition_resolution_state"] == "non_definition_token"
    assert trace["trace_state"] == "non_definition_token"
    assert trace["nodes"] == []
    assert trace["root_definition_refs"] == []


def test_operand_producer_must_match_encoded_address_and_time(tmp_path: Path) -> None:
    trace = _fixture(
        tmp_path / "exact-producer",
        [
            _row("1000", "1", "COPY", "def:1000:1:4", "def:1001:2:4"),
            _row("1001", "2", "COPY", "def:1001:2:4", "const:0x1:4"),
            _row("9999", "9", "COPY", "def:1001:2:4", "register:register:00000001:4"),
        ],
        "def:1000:1:4",
    )
    assert trace["trace_state"] == "closed"
    assert len(trace["operand_edges"]) == 1
    assert len(trace["unresolved_operands"]) == 0
