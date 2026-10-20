from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[4]
OUTPUT_DIR = Path(__file__).resolve().parent
PROGRAM_ID = "nevergone-1.0.9-armv7-libcocos2dcpp"
PROGRAM_SHA256 = "94b1ef6a9469e261183ac08199c5b0eb65c0c40b81918ca097bd32920828eb5e"
GRAPH_PATH = ROOT / "docs/evidence/semantic-program-graph-v3/nevergone-runtime-correlation-20261020/semantic-program-graph.jsonl"
FUNCTIONS = {
    "002d2f1c": ROOT / "docs/evidence/runtime-static-correlation-v1/nevergone-device-runtime-20261019/LoadGameLevels.pcode-flow.tsv",
    "00544a60": ROOT / "docs/evidence/runtime-static-correlation-v1/nevergone-device-runtime-20261019/CCFileUtilsAndroid-getFileData.pcode-flow.tsv",
}
PCODE_HEADER = (
    "function_entry", "op_address", "op_time", "opcode", "output", "inputs",
    "callee_entry", "callee_name",
)
PCODE_FORMAT = "REVENGINSTR.GhidraFunctionPcodeFlow/1"
INSTRUCTION_FORMAT = "REVENGINSTR.GhidraFunctionInstructions/1"
CROSSCHECK_FORMAT = "REVENGINSTR.SemanticProgramGraphCallReferenceCrosscheck/1"


def read_jsonl(path: Path) -> tuple[bytes, list[dict[str, Any]]]:
    raw = path.read_bytes()
    rows = [json.loads(line) for line in raw.splitlines() if line]
    if not rows or any(not isinstance(row, dict) for row in rows):
        raise ValueError(f"{path}: expected non-empty JSONL objects")
    return raw, rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("function_instructions", type=Path)
    args = parser.parse_args()

    instruction_raw, instruction_rows = read_jsonl(args.function_instructions)
    instruction_sha256 = hashlib.sha256(instruction_raw).hexdigest()
    instruction_sources: dict[str, tuple[int, dict[tuple[str, str], tuple[str, int]]]] = {}
    for record_index, row in enumerate(instruction_rows, 1):
        if row.get("format") != INSTRUCTION_FORMAT or row.get("found") is not True:
            raise ValueError(f"instruction record {record_index}: unsupported or missing function")
        entry = str(row["resolved_address"]).removeprefix("0x").lower()
        calls: dict[tuple[str, str], tuple[str, int]] = {}
        for instruction_index, instruction in enumerate(row["instructions"], 1):
            address = instruction["address"].removeprefix("0x").lower()
            for reference in instruction["references"]:
                reference_type = reference["type"]
                if "CALL" not in reference_type:
                    continue
                target = reference["to"].removeprefix("0x").lower()
                key = (address, target)
                if key in calls:
                    raise ValueError(f"instruction record {record_index}: duplicate call reference {key}")
                calls[key] = (reference_type, instruction_index)
        if entry in instruction_sources:
            raise ValueError(f"instruction record {record_index}: duplicate function entry {entry}")
        instruction_sources[entry] = (record_index, calls)

    if set(instruction_sources) != set(FUNCTIONS):
        raise ValueError("instruction export must contain exactly the two selected functions")

    pcode_calls: dict[tuple[str, str, str], tuple[str, int]] = {}
    for entry, path in FUNCTIONS.items():
        raw = path.read_bytes()
        digest = hashlib.sha256(raw).hexdigest()
        with path.open(encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle, delimiter="\t", strict=True)
            if tuple(reader.fieldnames or ()) != PCODE_HEADER:
                raise ValueError(f"{path}: unexpected P-code flow header")
            for record_index, row in enumerate(reader, 1):
                if row["function_entry"].lower() != entry or row["opcode"] != "CALL":
                    continue
                if row["callee_entry"] in {"", "-"}:
                    raise ValueError(f"{path}: direct CALL at {row['op_address']} lacks a target")
                key = (entry, row["op_address"].lower(), row["callee_entry"].lower())
                if key in pcode_calls:
                    raise ValueError(f"{path}: duplicate direct call {key}")
                pcode_calls[key] = (digest, record_index)

    reference_calls = {
        (entry, address, target)
        for entry, (_record_index, calls) in instruction_sources.items()
        for address, target in calls
    }
    if set(pcode_calls) != reference_calls:
        missing = sorted(set(pcode_calls) - reference_calls)
        unexpected = sorted(reference_calls - set(pcode_calls))
        raise ValueError(f"P-code and instruction references differ: missing={missing}, unexpected={unexpected}")

    graph_raw, graph_rows = read_jsonl(GRAPH_PATH)
    if len(graph_rows) != 1:
        raise ValueError("expected one semantic program graph record")
    graph = graph_rows[0]
    if graph.get("program_id") != PROGRAM_ID:
        raise ValueError("semantic graph program id changed")
    graph_sha256 = hashlib.sha256(graph_raw).hexdigest()
    function_nodes = {
        node["entry"].lower(): node["id"]
        for node in graph["nodes"]
        if node.get("kind") == "function"
    }
    operation_nodes = {
        (node["function_entry"].lower(), node["operation_address"].lower(), node["opcode"]): node["id"]
        for node in graph["nodes"]
        if node.get("kind") == "operation"
    }
    nodes_by_id = {node["id"]: node for node in graph["nodes"]}
    graph_calls: set[tuple[str, str, str]] = set()
    for edge in graph["edges"]:
        if edge.get("relation") != "calls":
            continue
        source = nodes_by_id.get(edge["from"])
        target = nodes_by_id.get(edge["to"])
        if source and target and source.get("function_entry", "").lower() in FUNCTIONS:
            graph_calls.add((source["function_entry"].lower(), source["operation_address"].lower(), target["entry"].lower()))
    if graph_calls != set(pcode_calls):
        raise ValueError("semantic graph call edges differ from selected P-code calls")

    crosscheck_rows = []
    scope_node_ids: set[str] = set()
    gold_edges = []
    for entry, address, target in sorted(pcode_calls):
        instruction_record_index, calls = instruction_sources[entry]
        reference_type, instruction_index = calls[(address, target)]
        operation_id = operation_nodes[(entry, address, "CALL")]
        target_id = function_nodes[target]
        scope_node_ids.update((operation_id, target_id))
        pcode_sha256, pcode_record_index = pcode_calls[(entry, address, target)]
        crosscheck_rows.append({
            "format": CROSSCHECK_FORMAT,
            "program_id": PROGRAM_ID,
            "program_sha256": PROGRAM_SHA256,
            "function_entry": entry,
            "operation_address": address,
            "target_entry": target,
            "reference_type": reference_type,
            "instruction_index": instruction_index,
            "instruction_export_sha256": instruction_sha256,
            "instruction_record_index": instruction_record_index,
            "pcode_flow_sha256": pcode_sha256,
            "pcode_record_index": pcode_record_index,
            "graph_sha256": graph_sha256,
            "status": "exact_match",
        })
        gold_edges.append({
            "from": operation_id,
            "to": target_id,
            "relation": "calls",
            "evidence_refs": [{
                "artifact_sha256": "",
                "record_index": len(crosscheck_rows),
                "source_format": CROSSCHECK_FORMAT,
            }],
        })

    crosscheck_path = OUTPUT_DIR / "direct-call-crosscheck.jsonl"
    crosscheck_raw = "".join(json.dumps(row, sort_keys=True) + "\n" for row in crosscheck_rows).encode()
    crosscheck_sha256 = hashlib.sha256(crosscheck_raw).hexdigest()
    crosscheck_path.write_bytes(crosscheck_raw)
    for edge in gold_edges:
        edge["evidence_refs"][0]["artifact_sha256"] = crosscheck_sha256

    gold = {
        "format": "REVENGINSTR.SemanticProgramGraphGold/1",
        "subgraph_id": "nevergone-runtime-resource-calls-20261020",
        "dataset_id": "nevergone-runtime-resource-calls-20261020",
        "split_id": "manual-audit",
        "program_id": PROGRAM_ID,
        "graph_id": graph["graph_id"],
        "scope_node_ids": sorted(scope_node_ids),
        "complete_relations": ["calls"],
        "edges": gold_edges,
        "adjudication_status": "adjudicated",
    }
    gold_path = OUTPUT_DIR / "gold-subgraphs.jsonl"
    gold_path.write_text(json.dumps(gold, sort_keys=True) + "\n", encoding="utf-8")
    print(f"direct calls cross-checked: {len(crosscheck_rows)}")
    print(f"FunctionInstructions SHA-256: {instruction_sha256}")
    print(f"cross-check output: {crosscheck_path}")
    print(f"gold output: {gold_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
