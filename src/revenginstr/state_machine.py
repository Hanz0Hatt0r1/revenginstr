"""Find bounded structural candidates for field-controlled state transitions."""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from revenginstr.evidence.structural import COMPARE_OPS

FORMAT = "REVENGINSTR.StateMachineCandidateAudit/1"
CFG_FORMAT = "REVENGINSTR.GhidraFunctionPcodeCFG/3"
LOAD_FORMAT = "REVENGINSTR.GhidraParameterLoadField/1"
STORE_FORMAT = "REVENGINSTR.GhidraMemoryStoreAccess/1"
CLAIM_SCOPE = (
    "Single-function structural candidate only; no state semantics, branch truth polarity, "
    "path feasibility, or runtime value-flow claim."
)
CFG_OPERATION_FIELDS = {
    "address", "time", "opcode", "memory_space", "memory_width_bytes",
    "memory_physical_space", "memory_pointer_width_bytes",
}
LOAD_HEADER = (
    "format", "function_entry", "function_name", "load_address", "load_time",
    "base_parameter_index", "field_offset", "address_pattern", "value_size",
    "value_token", "status",
)
PCODE_HEADER = (
    "function_entry", "op_address", "op_time", "opcode", "output", "inputs",
    "callee_entry", "callee_name",
)
_REASONS = [
    "parameter_field_load_directly_compared",
    "comparison_result_controls_conditional_branch",
    "same_parameter_offset_store_reachable_from_one_successor",
]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_tsv(path: Path, expected_header: tuple[str, ...]) -> tuple[str, list[dict[str, str]]]:
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"{path}: input must be UTF-8") from error
    reader = csv.DictReader(io.StringIO(text, newline=""), delimiter="\t", strict=True)
    if tuple(reader.fieldnames or ()) != expected_header:
        raise ValueError(f"{path}: unexpected TSV header")
    rows = []
    for record_index, row in enumerate(reader, 1):
        if None in row or any(value is None for value in row.values()):
            raise ValueError(f"{path}: malformed TSV record {record_index}")
        rows.append(row)
    return hashlib.sha256(raw).hexdigest(), rows


def _read_jsonl(path: Path) -> tuple[str, list[dict[str, Any]]]:
    raw = path.read_bytes()
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ValueError(f"{path}: input must be UTF-8") from error
    rows = []
    for line_no, line in enumerate(lines, 1):
        if not line.strip():
            raise ValueError(f"{path}:{line_no}: blank JSONL record")
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"{path}:{line_no}: invalid JSON") from error
        if not isinstance(row, dict):
            raise ValueError(f"{path}:{line_no}: expected an object")
        rows.append(row)
    return hashlib.sha256(raw).hexdigest(), rows


def _decimal(value: str, field: str, where: str) -> int:
    if not value.isascii() or not value.isdecimal():
        raise ValueError(f"{where}: invalid {field}")
    return int(value)


def _token_list(value: str, where: str) -> list[str]:
    if not value or value == "-":
        return []
    tokens = value.split(";")
    if any(not token for token in tokens):
        raise ValueError(f"{where}: malformed inputs cell")
    return tokens


def _cfg_index(
    rows: list[dict[str, Any]],
) -> tuple[str, dict[str, dict[str, Any]], dict[str, dict[tuple[str, int], int]]]:
    if not rows:
        raise ValueError("CFG/3 input must not be empty")
    program_id: str | None = None
    cfgs: dict[str, dict[str, Any]] = {}
    operation_blocks: dict[str, dict[tuple[str, int], int]] = {}
    for cfg_index, cfg in enumerate(rows, 1):
        if cfg.get("format") != CFG_FORMAT:
            raise ValueError(f"CFG row {cfg_index}: unsupported format")
        current_program = cfg.get("program_id")
        function_entry = cfg.get("function_entry")
        if not isinstance(current_program, str) or not current_program:
            raise ValueError(f"CFG row {cfg_index}: invalid program_id")
        if not isinstance(function_entry, str) or not function_entry or function_entry in cfgs:
            raise ValueError(f"CFG row {cfg_index}: invalid or duplicate function_entry")
        if program_id is None:
            program_id = current_program
        elif program_id != current_program:
            raise ValueError("CFG rows contain multiple program ids")
        blocks = cfg.get("blocks")
        entry = cfg.get("entry_block_index")
        if (
            not isinstance(blocks, list)
            or isinstance(entry, bool) or not isinstance(entry, int)
        ):
            raise ValueError(f"CFG row {cfg_index}: invalid blocks or entry block")
        by_index: dict[int, dict[str, Any]] = {}
        op_blocks: dict[tuple[str, int], int] = {}
        op_positions: dict[tuple[str, int], tuple[int, int]] = {}
        opcodes: dict[tuple[str, int], str] = {}
        for block in blocks:
            if not isinstance(block, dict):
                raise ValueError(f"CFG row {cfg_index}: invalid block")
            block_index = block.get("block_index")
            if isinstance(block_index, bool) or not isinstance(block_index, int) or block_index in by_index:
                raise ValueError(f"CFG row {cfg_index}: invalid or duplicate block index")
            operations = block.get("operations")
            successors = block.get("successors")
            if not isinstance(operations, list) or not isinstance(successors, list):
                raise ValueError(f"CFG row {cfg_index}: invalid block operations or successors")
            if (
                any(isinstance(successor, bool) or not isinstance(successor, int) for successor in successors)
                or len(successors) != len(set(successors))
            ):
                raise ValueError(f"CFG row {cfg_index}: invalid block successors")
            for operation_index, operation in enumerate(operations):
                if not isinstance(operation, dict) or set(operation) != CFG_OPERATION_FIELDS:
                    raise ValueError(f"CFG row {cfg_index}: invalid CFG/3 operation fields")
                address, time, opcode = operation.get("address"), operation.get("time"), operation.get("opcode")
                if (
                    not isinstance(address, str) or not address
                    or isinstance(time, bool) or not isinstance(time, int) or time < 0
                    or not isinstance(opcode, str) or not opcode
                ):
                    raise ValueError(f"CFG row {cfg_index}: invalid operation key")
                key = (address, time)
                if key in op_blocks:
                    raise ValueError(f"CFG row {cfg_index}: duplicate operation key")
                op_blocks[key] = block_index
                op_positions[key] = (block_index, operation_index)
                opcodes[key] = opcode
            by_index[block_index] = {"successors": successors, "operations": operations}
        if entry not in by_index:
            raise ValueError(f"CFG row {cfg_index}: entry block is missing")
        for block in by_index.values():
            if set(block["successors"]) - by_index.keys():
                raise ValueError(f"CFG row {cfg_index}: successor references an unknown block")
        cfgs[function_entry] = {
            "record_index": cfg_index,
            "entry_block_index": entry,
            "blocks": by_index,
            "operation_opcodes": opcodes,
            "operation_positions": op_positions,
        }
        operation_blocks[function_entry] = op_blocks
    return program_id or "", cfgs, operation_blocks


def _reachable(blocks: dict[int, dict[str, Any]], start: int) -> set[int]:
    reached = set()
    pending = [start]
    while pending:
        block_index = pending.pop()
        if block_index in reached:
            continue
        reached.add(block_index)
        pending.extend(blocks[block_index]["successors"])
    return reached


def _pcode_index(rows: list[dict[str, str]]) -> tuple[dict[str, list[dict[str, Any]]], dict[str, dict[tuple[str, int], dict[str, Any]]]]:
    by_function: dict[str, list[dict[str, Any]]] = defaultdict(list)
    by_key: dict[str, dict[tuple[str, int], dict[str, Any]]] = defaultdict(dict)
    for record_index, row in enumerate(rows, 1):
        where = f"P-code record {record_index}"
        function_entry = row.get("function_entry", "")
        address = row.get("op_address", "")
        opcode = row.get("opcode", "")
        if not function_entry or not address or not opcode:
            raise ValueError(f"{where}: missing operation identity")
        time = _decimal(row.get("op_time", ""), "op_time", where)
        output = row.get("output", "")
        if not output:
            raise ValueError(f"{where}: missing output cell")
        inputs = _token_list(row.get("inputs", ""), where)
        operation = {
            "record_index": record_index,
            "address": address,
            "time": time,
            "opcode": opcode,
            "output": None if output == "-" else output,
            "inputs": inputs,
        }
        key = (address, time)
        if key in by_key[function_entry]:
            raise ValueError(f"{where}: duplicate function/address/time key")
        by_key[function_entry][key] = operation
        by_function[function_entry].append(operation)
    return by_function, by_key


def build_state_machine_candidates(
    cfg_rows: list[dict[str, Any]],
    pcode_rows: list[dict[str, str]],
    parameter_load_rows: list[dict[str, str]],
    memory_store_rows: list[dict[str, Any]],
    *,
    cfg_sha256: str,
    pcode_sha256: str,
    parameter_load_sha256: str,
    memory_store_sha256: str,
    max_candidates: int = 100_000,
) -> dict[str, Any]:
    """Emit narrow compare/branch/same-field-write structural candidates."""
    if isinstance(max_candidates, bool) or not isinstance(max_candidates, int) or max_candidates < 1:
        raise ValueError("max_candidates must be positive")
    for name, digest in (
        ("CFG", cfg_sha256), ("P-code flow", pcode_sha256),
        ("parameter loads", parameter_load_sha256), ("memory stores", memory_store_sha256),
    ):
        if not isinstance(digest, str) or len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise ValueError(f"{name}: invalid SHA-256")

    program_id, cfgs, cfg_op_blocks = _cfg_index(cfg_rows)
    pcode_by_function, pcode_by_key = _pcode_index(pcode_rows)
    if set(cfgs) != set(pcode_by_function):
        raise ValueError("CFG and P-code function populations differ")

    pcode_operation_count = 0
    store_keys: set[tuple[str, str, int]] = set()
    load_by_key: dict[tuple[str, str, int], dict[str, Any]] = {}
    token_loads: dict[str, dict[str, list[dict[str, Any]]]] = defaultdict(lambda: defaultdict(list))
    for function_entry in pcode_by_function:
        cfg_keys = cfg_op_blocks[function_entry]
        flow_keys = pcode_by_key[function_entry]
        if set(cfg_keys) != set(flow_keys):
            raise ValueError(f"function {function_entry!r}: CFG and P-code operation populations differ")
        for key, operation in flow_keys.items():
            cfg_opcode = cfgs[function_entry]["operation_opcodes"][key]
            if cfg_opcode != operation["opcode"]:
                raise ValueError(f"function {function_entry!r}: CFG/P-code opcode mismatch at {key}")
            if operation["opcode"] == "STORE":
                store_keys.add((function_entry, key[0], key[1]))
            pcode_operation_count += 1

    for record_index, row in enumerate(parameter_load_rows, 1):
        where = f"parameter load record {record_index}"
        if row.get("format") != LOAD_FORMAT or row.get("status") != "parameter_field_load":
            raise ValueError(f"{where}: unsupported format or status")
        function_entry = row.get("function_entry", "")
        if function_entry not in pcode_by_key:
            raise ValueError(f"{where}: function is absent from P-code flow")
        address = row.get("load_address", "")
        time = _decimal(row.get("load_time", ""), "load_time", where)
        key = (function_entry, address, time)
        if key in load_by_key:
            raise ValueError(f"{where}: duplicate load key")
        operation = pcode_by_key[function_entry].get((address, time))
        if operation is None or operation["opcode"] != "LOAD" or operation["output"] != row.get("value_token"):
            raise ValueError(f"{where}: does not join to the exact P-code LOAD output")
        try:
            offset_bytes = int(row.get("field_offset", ""), 0)
        except ValueError as error:
            raise ValueError(f"{where}: invalid field_offset") from error
        load = {
            "record_index": record_index,
            "parameter_index": _decimal(row.get("base_parameter_index", ""), "base_parameter_index", where),
            "field_offset_bytes": offset_bytes,
            "operation": operation,
        }
        load_by_key[key] = load
        token_loads[function_entry][operation["output"]].append(load)

    store_rows: dict[tuple[str, str, int], dict[str, Any]] = {}
    unresolved_store_count = 0
    for record_index, row in enumerate(memory_store_rows, 1):
        where = f"memory store record {record_index}"
        if row.get("format") != STORE_FORMAT or row.get("opcode") != "STORE":
            raise ValueError(f"{where}: unsupported format or opcode")
        if row.get("program_id") != program_id:
            raise ValueError(f"{where}: program_id disagrees with CFG")
        function_entry = row.get("function_entry", "")
        address, time = row.get("address", ""), row.get("time")
        if not isinstance(function_entry, str) or not function_entry or not isinstance(address, str) or not address:
            raise ValueError(f"{where}: invalid function/address")
        if isinstance(time, bool) or not isinstance(time, int) or time < 0:
            raise ValueError(f"{where}: invalid operation time")
        key = (function_entry, address, time)
        if key in store_rows:
            raise ValueError(f"{where}: duplicate store key")
        operation = pcode_by_key.get(function_entry, {}).get((address, time))
        if operation is None or operation["opcode"] != "STORE":
            raise ValueError(f"{where}: does not join to an exact P-code STORE")
        status = row.get("location_status")
        if status not in {"parameter_rooted_constant_offset", "unresolved"}:
            raise ValueError(f"{where}: unsupported location_status")
        store = {"record_index": record_index, "row": row, "operation": operation}
        if status == "parameter_rooted_constant_offset":
            root_parameter_index, offset_bytes = row.get("root_parameter_index"), row.get("offset_bytes")
            if (
                isinstance(root_parameter_index, bool) or not isinstance(root_parameter_index, int)
                or isinstance(offset_bytes, bool) or not isinstance(offset_bytes, int)
            ):
                raise ValueError(f"{where}: rooted store has missing parameter or offset")
            store["parameter_index"] = root_parameter_index
            store["field_offset_bytes"] = offset_bytes
        else:
            unresolved_store_count += 1
        store_rows[key] = store
    if set(store_rows) != store_keys:
        raise ValueError("memory store sidecar and P-code STORE populations differ")

    for function_entry, cfg in cfgs.items():
        blocks = cfg["blocks"]
        _reachable(blocks, cfg["entry_block_index"])
        for load_key in load_by_key:
            if load_key[0] == function_entry and load_key[1:] not in cfg_op_blocks[function_entry]:
                raise ValueError(f"function {function_entry!r}: parameter load is absent from CFG")

    candidates = []
    candidate_ids: set[str] = set()
    for function_entry, operations in pcode_by_function.items():
        cfg = cfgs[function_entry]
        blocks = cfg["blocks"]
        reachable_cache: dict[int, set[int]] = {}

        def reachable_from(block_index: int) -> set[int]:
            if block_index not in reachable_cache:
                reachable_cache[block_index] = _reachable(blocks, block_index)
            return reachable_cache[block_index]

        reachable_blocks = reachable_from(cfg["entry_block_index"])
        op_blocks = cfg_op_blocks[function_entry]
        op_positions = cfg["operation_positions"]
        comparisons_by_input: dict[str, list[dict[str, Any]]] = defaultdict(list)
        branches_by_condition: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for operation in operations:
            if operation["opcode"] in COMPARE_OPS and operation["output"]:
                for token in operation["inputs"]:
                    comparisons_by_input[token].append(operation)
            elif operation["opcode"] == "CBRANCH" and len(operation["inputs"]) == 2:
                # P-code CBRANCH input 0 is the target; input 1 is the condition.
                branches_by_condition[operation["inputs"][1]].append(operation)
        stores_by_field: dict[tuple[int, int], list[dict[str, Any]]] = defaultdict(list)
        for (store_function, _address, _time), store in store_rows.items():
            if store_function == function_entry and store["row"]["location_status"] == "parameter_rooted_constant_offset":
                stores_by_field[(store["parameter_index"], store["field_offset_bytes"])].append(store)

        for token, load_rows_for_token in token_loads[function_entry].items():
            for load_row in load_rows_for_token:
                load_op = load_row["operation"]
                load_key = (load_op["address"], load_op["time"])
                load_block, load_position = op_positions[load_key]
                if load_block not in reachable_blocks:
                    continue
                field_key = (load_row["parameter_index"], load_row["field_offset_bytes"])
                for comparison in comparisons_by_input[token]:
                    comparison_key = (comparison["address"], comparison["time"])
                    comparison_block, comparison_position = op_positions[comparison_key]
                    if comparison_block not in reachable_blocks:
                        continue
                    if comparison_block == load_block:
                        if comparison_position <= load_position:
                            continue
                    elif comparison_block not in reachable_from(load_block):
                        continue
                    for branch in branches_by_condition[comparison["output"]]:
                        branch_key = (branch["address"], branch["time"])
                        branch_block, branch_position = op_positions[branch_key]
                        if branch_block not in reachable_blocks:
                            continue
                        if branch_block == comparison_block:
                            if branch_position <= comparison_position:
                                continue
                        elif branch_block not in reachable_from(comparison_block):
                            continue
                        if branch_position != len(blocks[branch_block]["operations"]) - 1:
                            continue
                        successors = sorted(blocks[branch_block]["successors"])
                        if len(successors) != 2:
                            continue
                        successor_reachability = {
                            successor: reachable_from(successor) for successor in successors
                        }
                        for store in stores_by_field[field_key]:
                            store_op = store["operation"]
                            store_block = op_blocks[(store_op["address"], store_op["time"])]
                            if store_block not in reachable_blocks or store_block == branch_block:
                                continue
                            reaches_from = [
                                successor for successor in successors
                                if store_block in successor_reachability[successor]
                            ]
                            if len(reaches_from) != 1:
                                continue
                            identity = "\0".join(map(str, (
                                function_entry, load_row["record_index"], comparison["record_index"],
                                branch["record_index"], store["record_index"],
                            ))).encode("utf-8")
                            candidate_id = hashlib.sha256(
                                cfg_sha256.encode("ascii") + bytes.fromhex(pcode_sha256)
                                + bytes.fromhex(parameter_load_sha256) + bytes.fromhex(memory_store_sha256)
                                + identity
                            ).hexdigest()
                            if candidate_id in candidate_ids:
                                continue
                            candidate_ids.add(candidate_id)
                            candidates.append({
                                "candidate_id": candidate_id,
                                "function_entry": function_entry,
                                "field": {
                                    "root_parameter_index": load_row["parameter_index"],
                                    "offset_bytes": load_row["field_offset_bytes"],
                                },
                                "load": {
                                    "operation_address": load_op["address"],
                                    "operation_time": load_op["time"],
                                    "parameter_load_record_index": load_row["record_index"],
                                    "pcode_flow_record_index": load_op["record_index"],
                                },
                                "comparison": {
                                    "opcode": comparison["opcode"],
                                    "operation_address": comparison["address"],
                                    "operation_time": comparison["time"],
                                    "pcode_flow_record_index": comparison["record_index"],
                                },
                                "branch": {
                                    "operation_address": branch["address"],
                                    "operation_time": branch["time"],
                                    "pcode_flow_record_index": branch["record_index"],
                                    "cfg_record_index": cfg["record_index"],
                                    "cfg_block_index": branch_block,
                                    "successor_block_indices": successors,
                                    "write_reachable_successor_index": reaches_from[0],
                                },
                                "write": {
                                    "operation_address": store_op["address"],
                                    "operation_time": store_op["time"],
                                    "pcode_flow_record_index": store_op["record_index"],
                                    "memory_store_record_index": store["record_index"],
                                    "cfg_record_index": cfg["record_index"],
                                    "cfg_block_index": store_block,
                                },
                                "reason_codes": list(_REASONS),
                            })
                            if len(candidates) > max_candidates:
                                raise ValueError(f"state-machine candidate budget exceeded: {max_candidates}")

    candidates.sort(key=lambda row: (
        row["function_entry"], row["branch"]["operation_time"], row["field"]["root_parameter_index"],
        row["field"]["offset_bytes"], row["write"]["operation_time"], row["candidate_id"],
    ))
    return {
        "format": FORMAT,
        "program_id": program_id,
        "claim_scope": CLAIM_SCOPE,
        "source": {
            "cfg_sha256": cfg_sha256,
            "pcode_flow_sha256": pcode_sha256,
            "parameter_load_sha256": parameter_load_sha256,
            "memory_store_sha256": memory_store_sha256,
            "function_count": len(cfgs),
            "pcode_operations": pcode_operation_count,
            "parameter_load_rows": len(load_by_key),
            "memory_store_rows": len(store_rows),
            "unresolved_store_rows": unresolved_store_count,
            "candidate_count": len(candidates),
        },
        "candidates": candidates,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cfg_v3_jsonl", type=Path)
    parser.add_argument("pcode_flow_tsv", type=Path)
    parser.add_argument("parameter_loads_tsv", type=Path)
    parser.add_argument("memory_stores_jsonl", type=Path)
    parser.add_argument("--max-candidates", type=int, default=100_000)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    cfg_sha256, cfg_rows = _read_jsonl(args.cfg_v3_jsonl)
    pcode_sha256, pcode_rows = _read_tsv(args.pcode_flow_tsv, PCODE_HEADER)
    loads_sha256, load_rows = _read_tsv(args.parameter_loads_tsv, LOAD_HEADER)
    stores_sha256, store_rows = _read_jsonl(args.memory_stores_jsonl)
    report = build_state_machine_candidates(
        cfg_rows, pcode_rows, load_rows, store_rows,
        cfg_sha256=cfg_sha256, pcode_sha256=pcode_sha256,
        parameter_load_sha256=loads_sha256, memory_store_sha256=stores_sha256,
        max_candidates=args.max_candidates,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("functions:", report["source"]["function_count"])
    print("candidates:", report["source"]["candidate_count"])
    print("output:", args.output)
    return 0
