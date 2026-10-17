from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

from jsonschema import Draft202012Validator
import pytest

from revenginstr.receiver.field_flow import audit_field_store_load_dominance
from revenginstr.receiver.interprocedural_memory import (
    PARAMETER_ROOT_FORMAT,
    PARAMETER_ROOT_HEADER,
    build_interprocedural_memory_effects,
)
from revenginstr.receiver.provenance import (
    PARAMETER_LOAD_FORMAT,
    PARAMETER_STORE_FORMAT,
    build_field_access_pair_graphs,
)

ROOT = Path(__file__).resolve().parents[1]
FLOW_HEADER = (
    "function_entry", "op_address", "op_time", "opcode", "output", "inputs",
    "callee_entry", "callee_name",
)


def _flow(entry: str, operations: list[tuple[str, int, str, str, str]]) -> list[dict[str, str]]:
    return [
        {
            "function_entry": entry,
            "op_address": address,
            "op_time": str(time),
            "opcode": opcode,
            "output": "-",
            "inputs": inputs,
            "callee_entry": callee,
            "callee_name": "-" if callee == "-" else f"FUN_{callee}",
        }
        for address, time, opcode, inputs, callee in operations
    ]


def _cfg(entry: str, rows: list[dict[str, str]]) -> dict:
    operations = []
    for row in rows:
        is_memory = row["opcode"] in {"STORE", "LOAD"}
        operations.append({
            "address": row["op_address"],
            "time": int(row["op_time"]),
            "opcode": row["opcode"],
            "memory_space": "ram" if is_memory else None,
            "memory_width_bytes": 4 if is_memory else None,
            "memory_physical_space": "ram-physical" if is_memory else None,
            "memory_pointer_width_bytes": 4 if is_memory else None,
        })
    return {
        "format": "REVENGINSTR.GhidraFunctionPcodeCFG/3",
        "program_id": "synthetic:interprocedural",
        "function_entry": entry,
        "entry_block_index": 0,
        "blocks": [{
            "block_index": 0,
            "start_address": entry,
            "stop_address": operations[-1]["address"],
            "operations": operations,
            "successors": [],
        }],
    }


def _store_fact(entry: str, address: str, time: int, offset: int, root: int | None = 0) -> dict:
    return {
        "format": "REVENGINSTR.GhidraMemoryStoreAccess/1",
        "program_id": "synthetic:interprocedural",
        "function_entry": entry,
        "address": address,
        "time": time,
        "opcode": "STORE",
        "memory_space": "ram",
        "memory_physical_space": "ram-physical",
        "memory_width_bytes": 4,
        "memory_pointer_width_bytes": 4,
        "memory_space_size_bits": 32,
        "memory_addressable_unit_bytes": 1,
        "pointer_token": f"input:{entry}:{root}",
        "root_parameter_index": root,
        "offset_bytes": offset if root is not None else None,
        "location_status": "parameter_rooted_constant_offset" if root is not None else "unresolved",
        "destination_pattern": "ptrsub" if root is not None else "opaque",
        "address_expression_ops": [],
    }


def _pair_graphs():
    store = [{
        "format": PARAMETER_STORE_FORMAT, "function_entry": "00401000", "function_name": "root",
        "store_address": "00401020", "store_time": "7", "destination_parameter_index": "0",
        "destination_offset": "0x10", "destination_pattern": "ptrsub", "source_parameter_index": "1",
        "value_size": "4", "status": "parameter_to_parameter_field",
    }]
    load = [{
        "format": PARAMETER_LOAD_FORMAT, "function_entry": "00401000", "function_name": "root",
        "load_address": "00401030", "load_time": "11", "base_parameter_index": "0",
        "field_offset": "0x10", "address_pattern": "ptrsub", "value_size": "4",
        "value_token": "def:LOAD@00401030:11:4", "status": "parameter_field_load",
    }]
    return build_field_access_pair_graphs(store, load, program_id="synthetic:interprocedural")


def _write_tsv(path: Path, header: tuple[str, ...], rows: list[dict[str, str]]) -> None:
    with path.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=header, delimiter="\t", lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def _dataset(
    tmp_path: Path, *, offset: int = 0x20, cycle: bool = False,
    root_link: bool = True, callind: bool = False, missing_store_fact: bool = False,
):
    root_ops = [
        ("00401020", 7, "STORE", "const:0x0:4;input:root:0:4", "-"),
        ("00401024", 10, "CALL", "input:root:0:4", "00402000"),
        ("00401030", 11, "LOAD", "const:0x0:4;input:root:0:4", "-"),
    ]
    middle_ops = [("00402010", 1, "STORE", "const:0x0:4;input:middle:0:4", "-")]
    leaf_ops: list[tuple[str, int, str, str, str]] = []
    if cycle:
        middle_ops.append(("00402020", 2, "CALL", "input:middle:0:4", "00403000"))
        leaf_ops = [
            ("00403010", 1, "STORE", "const:0x0:4;input:leaf:0:4", "-"),
            ("00403020", 2, "CALL", "input:leaf:0:4", "00402000"),
        ]
    elif callind:
        middle_ops.append(("00402020", 2, "CALLIND", "input:middle:0:4", "-"))
    flows = {
        "00401000": _flow("00401000", root_ops),
        "00402000": _flow("00402000", middle_ops),
    }
    if leaf_ops:
        flows["00403000"] = _flow("00403000", leaf_ops)
    pair_path = tmp_path / "pairs.jsonl"
    cfg_path = tmp_path / "cfg.jsonl"
    access_path = tmp_path / "stores.jsonl"
    roots_path = tmp_path / "roots.tsv"
    pair_graphs = _pair_graphs()
    pair_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in pair_graphs))
    cfg_rows = [_cfg(entry, rows) for entry, rows in flows.items()]
    cfg_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in cfg_rows))
    stores = [_store_fact("00401000", "00401020", 7, 0x10)]
    if not missing_store_fact:
        stores.append(_store_fact("00402000", "00402010", 1, offset))
    if cycle:
        stores.append(_store_fact("00403000", "00403010", 1, offset))
    access_path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in stores))
    roots = []
    if root_link:
        roots.append({
            "format": PARAMETER_ROOT_FORMAT, "plan_id": "root-middle-p0", "callee_entry": "00402000",
            "parameter_index": "0", "caller_entry": "00401000", "caller_call_site": "00401024",
            "caller_parameter_index": "0", "argument_node_id": "0", "status": "direct_parameter_root",
        })
    if cycle:
        roots.extend([
            {"format": PARAMETER_ROOT_FORMAT, "plan_id": "middle-leaf-p0", "callee_entry": "00403000",
             "parameter_index": "0", "caller_entry": "00402000", "caller_call_site": "00402020",
             "caller_parameter_index": "0", "argument_node_id": "0", "status": "direct_parameter_root"},
            {"format": PARAMETER_ROOT_FORMAT, "plan_id": "leaf-middle-p0", "callee_entry": "00402000",
             "parameter_index": "0", "caller_entry": "00403000", "caller_call_site": "00403020",
             "caller_parameter_index": "0", "argument_node_id": "0", "status": "direct_parameter_root"},
        ])
    _write_tsv(roots_path, PARAMETER_ROOT_HEADER, roots)
    flow_paths = []
    for entry, rows in flows.items():
        path = tmp_path / f"{entry}.tsv"
        _write_tsv(path, FLOW_HEADER, rows)
        flow_paths.append((entry, path))
    return pair_path, cfg_path, access_path, roots_path, flow_paths, pair_graphs, cfg_rows, stores


def _analyze(tmp_path: Path, **options):
    pair_path, cfg_path, access_path, roots_path, flow_paths, pairs, cfg_rows, stores = _dataset(tmp_path, **options)
    effects = build_interprocedural_memory_effects(
        pair_path, cfg_path, access_path, roots_path, pcode_flows=flow_paths,
    )
    return effects, pair_path, cfg_path, access_path, pairs, cfg_rows, stores


def test_exact_root_disjoint_transitive_store_is_pair_specific_and_auditable(tmp_path: Path) -> None:
    effects, pair_path, cfg_path, access_path, pairs, cfg_rows, stores = _analyze(tmp_path)
    [effect] = effects
    schema = json.loads((ROOT / "schemas/ghidra-interprocedural-memory-effect-v1.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(effect)
    assert effect["status"] == "no_aliasing_memory_effect"
    assert effect["non_aliasing_store_record_indices"] == [2]

    encoded = (json.dumps(effect, sort_keys=True) + "\n").encode()
    audit = audit_field_store_load_dominance(
        pairs, cfg_rows, pair_graph_sha256=hashlib.sha256(pair_path.read_bytes()).hexdigest(),
        cfg_sha256=hashlib.sha256(cfg_path.read_bytes()).hexdigest(),
        memory_store_access_rows=stores, memory_store_access_sha256=hashlib.sha256(access_path.read_bytes()).hexdigest(),
        interprocedural_memory_effect_rows=effects,
        interprocedural_memory_effect_sha256=hashlib.sha256(encoded).hexdigest(),
    )
    audit_schema = json.loads((ROOT / "schemas/field-store-load-dominance-audit-v5.schema.json").read_text())
    Draft202012Validator.check_schema(audit_schema)
    Draft202012Validator(audit_schema).validate(audit[0])
    assert audit[0]["format"] == "REVENGINSTR.FieldStoreLoadDominanceAudit/5"
    assert audit[0]["status"] == "unique_cfg_store_candidate"


def test_overlap_missing_root_and_unknown_call_remain_barriers(tmp_path: Path) -> None:
    for options, expected in (
        ({"offset": 0x10}, "possible_aliasing_write"),
        ({"offset": 0x20, "root_link": False}, "possible_aliasing_write"),
        ({"offset": 0x20, "callind": True}, "unknown_effect"),
        ({"offset": 0x20, "missing_store_fact": True}, "unknown_effect"),
    ):
        case = tmp_path / expected / str(len(list(tmp_path.rglob("pairs.jsonl"))))
        case.mkdir(parents=True)
        effects, pair_path, cfg_path, access_path, pairs, cfg_rows, stores = _analyze(case, **options)
        assert effects[0]["status"] == expected, options
        audit = audit_field_store_load_dominance(
            pairs, cfg_rows, pair_graph_sha256=hashlib.sha256(pair_path.read_bytes()).hexdigest(),
            cfg_sha256=hashlib.sha256(cfg_path.read_bytes()).hexdigest(),
            memory_store_access_rows=stores, memory_store_access_sha256=hashlib.sha256(access_path.read_bytes()).hexdigest(),
            interprocedural_memory_effect_rows=effects,
            interprocedural_memory_effect_sha256=hashlib.sha256((json.dumps(effects[0], sort_keys=True) + "\n").encode()).hexdigest(),
        )
        assert audit[0]["status"] == "possible_intervening_memory_effect"


def test_exact_root_dataflow_terminates_cycles_without_losing_disjointness(tmp_path: Path) -> None:
    effects, *_ = _analyze(tmp_path, cycle=True, offset=0x20)
    assert effects[0]["status"] == "no_aliasing_memory_effect"
    assert effects[0]["provenance"]["closure_function_entries"] == ["00402000", "00403000"]
    assert effects[0]["non_aliasing_store_record_indices"] == [2, 3]


def test_consumer_rejects_interprocedural_sidecars_with_stale_or_unknown_pair_provenance(tmp_path: Path) -> None:
    effects, pair_path, cfg_path, access_path, pairs, cfg_rows, stores = _analyze(tmp_path)
    for field, value, expected in (
        ("field_pair_id", 'invalid-pair', "unknown field-access pair"),
        ("memory_store_access_sha256", "0" * 64, "provenance mismatch"),
    ):
        stale = json.loads(json.dumps(effects))
        if field == "field_pair_id":
            stale[0][field] = value
        else:
            stale[0]["provenance"][field] = value
        sidecar_sha = hashlib.sha256(
            (json.dumps(stale[0], sort_keys=True) + "\n").encode()
        ).hexdigest()
        with pytest.raises(ValueError, match=expected):
            audit_field_store_load_dominance(
                pairs,
                cfg_rows,
                pair_graph_sha256=hashlib.sha256(pair_path.read_bytes()).hexdigest(),
                cfg_sha256=hashlib.sha256(cfg_path.read_bytes()).hexdigest(),
                memory_store_access_rows=stores,
                memory_store_access_sha256=hashlib.sha256(access_path.read_bytes()).hexdigest(),
                interprocedural_memory_effect_rows=stale,
                interprocedural_memory_effect_sha256=sidecar_sha,
            )
