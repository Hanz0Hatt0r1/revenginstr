from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator

from revenginstr.runtime_indirect_call_correlation import (
    OBSERVATION_FORMAT,
    REPORT_FORMAT,
    main,
)
from revenginstr.runtime_static_correlation import CAPTURE_FORMAT, STATIC_IDENTITY_FORMAT
from revenginstr.semantic_program_graph import _read_jsonl, _stable_id

ROOT = Path(__file__).resolve().parents[1]
GRAPH_PATH = ROOT / "docs/evidence/semantic-program-graph-v3/nevergone-ccjoystick/semantic-program-graph.jsonl"
PROGRAM_MANIFEST_PATH = ROOT / "docs/evidence/semantic-program-graph-v3/nevergone-ccjoystick/manifest.json"
SCHEMAS = {
    name: json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))
    for name in (
        "runtime-indirect-call-observation-v1.schema.json",
        "runtime-indirect-call-correlation-v1.schema.json",
    )
}


def _inputs(tmp_path: Path):
    graphs, _ = _read_jsonl(GRAPH_PATH)
    graph = copy.deepcopy(graphs[0])
    direct_calls = [
        node for node in graph["nodes"]
        if node.get("kind") == "operation" and node.get("opcode") == "CALL"
    ]
    indirect_source = direct_calls[0]
    other_direct = direct_calls[1]
    old_id = indirect_source["id"]
    owner = indirect_source["function_entry"]
    address = indirect_source["operation_address"]
    operation_time = indirect_source["operation_time"]
    new_id = _stable_id("operation", [graph["program_id"], owner, address, operation_time, "CALLIND"])
    containing = next(
        edge for edge in graph["edges"]
        if edge["relation"] == "contains" and edge["to"] == old_id
    )
    graph["edges"] = [
        edge for edge in graph["edges"]
        if edge["from"] != old_id and edge["to"] != old_id
    ]
    graph["nodes"] = [node for node in graph["nodes"] if node["id"] != old_id]
    callind = dict(indirect_source)
    callind.update({
        "id": new_id,
        "opcode": "CALLIND",
        "kinds": ["indirect_call"],
        "call_target_state": "indirect",
        "target_entries": [],
    })
    graph["nodes"].append(callind)
    containing = {**containing, "to": new_id}
    containing["id"] = _stable_id("edge", [containing["from"], new_id, "contains"])
    graph["edges"].append(containing)

    graph_bytes = (json.dumps(graph, sort_keys=True) + "\n").encode()
    graph_sha256 = hashlib.sha256(graph_bytes).hexdigest()
    program = json.loads(PROGRAM_MANIFEST_PATH.read_text(encoding="utf-8"))
    identity = {
        "format": STATIC_IDENTITY_FORMAT,
        "program_id": graph["program_id"],
        "program_sha256": program["program_sha256"],
        "semantic_graph_sha256": graph_sha256,
        "static_image_base": "0x10000",
    }
    identity_bytes = (json.dumps(identity, sort_keys=True) + "\n").encode()
    capture = {
        "format": CAPTURE_FORMAT,
        "capture_id": "synthetic-indirect-call-correlation",
        "program_id": identity["program_id"],
        "program_sha256": identity["program_sha256"],
        "static_identity_sha256": hashlib.sha256(identity_bytes).hexdigest(),
        "runtime_module_base": "0x70000000",
        "sampling_status": "sampled",
        "sampling_gaps": [{"first_sequence": 1, "last_sequence": 1, "reason": "synthetic dropped call event"}],
    }
    delta = int(capture["runtime_module_base"], 16) - int(identity["static_image_base"], 16)
    target = indirect_source["target_entries"][0]

    def runtime(address: str) -> str:
        return hex(int(address, 16) + delta)

    observations = [
        {
            "format": OBSERVATION_FORMAT,
            "capture_id": capture["capture_id"],
            "sequence": 0,
            "caller_runtime_address": runtime(owner),
            "callsite_runtime_address": runtime(address),
            "target_runtime_address": runtime(target),
        },
        {
            "format": OBSERVATION_FORMAT,
            "capture_id": capture["capture_id"],
            "sequence": 2,
            "caller_runtime_address": runtime(owner),
            "callsite_runtime_address": runtime(address),
            "target_runtime_address": runtime("0x10001"),
        },
        {
            "format": OBSERVATION_FORMAT,
            "capture_id": capture["capture_id"],
            "sequence": 3,
            "caller_runtime_address": runtime(other_direct["function_entry"]),
            "callsite_runtime_address": runtime(other_direct["operation_address"]),
            "target_runtime_address": runtime(target),
        },
    ]
    graph_path = tmp_path / "graph.jsonl"
    graph_path.write_bytes(graph_bytes)
    identity_path = tmp_path / "identity.json"
    identity_path.write_bytes(identity_bytes)
    capture_path = tmp_path / "capture.json"
    capture_path.write_text(json.dumps(capture, sort_keys=True) + "\n", encoding="utf-8")
    observations_path = tmp_path / "observations.jsonl"
    observations_path.write_text(
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in observations), encoding="utf-8",
    )
    return graph_path, identity_path, capture_path, observations_path, observations, callind, target


def test_runtime_indirect_call_cli_joins_exact_site_and_target_and_preserves_gaps(
    tmp_path: Path, capsys,
) -> None:
    graph, identity, capture, observations, rows, callind, target = _inputs(tmp_path)
    Draft202012Validator.check_schema(SCHEMAS["runtime-indirect-call-observation-v1.schema.json"])
    Draft202012Validator.check_schema(SCHEMAS["runtime-indirect-call-correlation-v1.schema.json"])
    for row in rows:
        Draft202012Validator(SCHEMAS["runtime-indirect-call-observation-v1.schema.json"]).validate(row)

    output = tmp_path / "report.json"
    assert main([
        str(graph), str(identity), str(capture), str(observations), "--output", str(output),
    ]) == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    Draft202012Validator(SCHEMAS["runtime-indirect-call-correlation-v1.schema.json"]).validate(report)

    assert report["format"] == REPORT_FORMAT
    assert report["summary"] == {
        "event_count": 3,
        "match_state_counts": {
            "matched": 1,
            "unmatched_callsite": 1,
            "unmatched_target": 1,
        },
    }
    assert report["sampling"]["gaps"] == [{
        "first_sequence": 1,
        "last_sequence": 1,
        "reason": "synthetic dropped call event",
    }]
    exact, missing_target, wrong_opcode_site = report["events"]
    assert exact["caller_match_state"] == exact["callsite_match_state"] == exact["target_match_state"] == "matched"
    assert exact["callsite_node_ids"] == [callind["id"]]
    assert exact["target_node_ids"] == [node["id"] for node in _read_jsonl(graph)[0][0]["nodes"] if node.get("kind") == "function" and node["entry"] == target]
    assert missing_target["callsite_match_state"] == "matched"
    assert missing_target["target_match_state"] == "unmatched"
    assert missing_target["target_address"] == "0x10001"
    assert wrong_opcode_site["callsite_match_state"] == "unmatched"
    assert wrong_opcode_site["match_state"] == "unmatched_callsite"
    assert "runtime indirect calls: 3" in capsys.readouterr().out
