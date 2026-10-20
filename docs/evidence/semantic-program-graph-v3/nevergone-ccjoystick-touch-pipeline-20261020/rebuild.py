#!/usr/bin/env python3
"""Rebuild the pinned Nevergone CCJoyStick touch-pipeline graph and queries."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

from revenginstr.effect_ir import build_function_effect_ir
from revenginstr.semantic_program_graph import build_semantic_program_graphs
from revenginstr.semantic_program_path_query import query_graphs as query_paths
from revenginstr.semantic_program_query import query_graphs
from revenginstr.receiver.field_flow import _index_cfg


ROOT = next(parent for parent in Path(__file__).resolve().parents if (parent / "pyproject.toml").is_file())
EVIDENCE = ROOT / "docs/evidence/semantic-program-graph-v3"
OWNER = EVIDENCE / "nevergone-ccjoystick-owner-methods-20261020"
HELPERS = EVIDENCE / "nevergone-ccjoystick-touch-helpers-20261020"
HERE = Path(__file__).resolve().parent
PROGRAM_ID = "nevergone:libcocos2dcpp.so"
TOUCH_FIELDS = ["0x11c", "0x120", "0x124", "0x128", "0x12c"]
PATH_QUERIES = [
    ("002a6300", "002a60c8", "path-callback-to-hitcheck.jsonl"),
    ("002a6300", "002a6284", "path-callback-to-began.jsonl"),
    ("002a63ec", "002a63a8", "path-callback-to-end.jsonl"),
]


def _read_jsonl(path: Path) -> tuple[list[dict[str, Any]], bytes]:
    raw = path.read_bytes()
    records = [json.loads(line) for line in raw.decode("utf-8").splitlines() if line.strip()]
    if not records:
        raise ValueError(f"{path}: JSONL input is empty")
    return records, raw


def _jsonl_bytes(records: list[dict[str, Any]]) -> bytes:
    return b"".join((json.dumps(record, sort_keys=True) + "\n").encode("utf-8") for record in records)


def _write(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(raw)


def rebuild(output_dir: Path) -> None:
    helper_effects = build_function_effect_ir(
        PROGRAM_ID,
        parameter_store_tsv=HELPERS / "parameter-stores.tsv",
        parameter_load_tsv=HELPERS / "parameter-loads.tsv",
        memory_store_access_jsonl=HELPERS / "memory-store-access.jsonl",
        pcode_flow_tsv=HELPERS / "pcode-flow.tsv",
    )
    callback_effects = build_function_effect_ir(
        PROGRAM_ID,
        pcode_flow_tsv=HERE / "callback-pcode-flow.tsv",
    )
    owner_effects, _ = _read_jsonl(OWNER / "function-effects.jsonl")
    effects = owner_effects + helper_effects + callback_effects
    effects.sort(key=lambda row: (row["program_id"], row["function_entry"]))
    if len({row["function_entry"] for row in effects}) != len(effects):
        raise ValueError("duplicate function entries in combined Effect IR")
    effects_raw = _jsonl_bytes(effects)
    _write(output_dir / "function-effects.jsonl", effects_raw)

    owner_maps, _ = _read_jsonl(OWNER / "type-layout-member-map.jsonl")
    helper_maps, _ = _read_jsonl(HELPERS / "touch-helper-type-layout-member-map.jsonl")
    member_maps = owner_maps + helper_maps
    member_maps.sort(key=lambda row: (row["program_id"], row["function_entry"], row["root_parameter_index"]))
    member_maps_raw = _jsonl_bytes(member_maps)
    _write(output_dir / "type-layout-member-map.jsonl", member_maps_raw)

    layout_rows, layout_raw = _read_jsonl(HELPERS / "type-layout-hypothesis.jsonl")
    graphs = build_semantic_program_graphs(
        effects,
        source_sha256=hashlib.sha256(effects_raw).hexdigest(),
        type_layout_rows=layout_rows,
        type_layout_sha256=hashlib.sha256(layout_raw).hexdigest(),
        type_layout_member_map_rows=member_maps,
        type_layout_member_map_sha256=hashlib.sha256(member_maps_raw).hexdigest(),
    )
    graph_raw = _jsonl_bytes(graphs)
    _write(output_dir / "semantic-program-graph.jsonl", graph_raw)
    graph_sha256 = hashlib.sha256(graph_raw).hexdigest()
    cfg_rows, cfg_raw = _read_jsonl(HERE / "callback-function-pcode-cfg.jsonl")
    cfg_index = _index_cfg(cfg_rows)
    cfg_sha256 = hashlib.sha256(cfg_raw).hexdigest()

    for source_entry, target_entry, filename in PATH_QUERIES:
        result = query_paths(
            graphs,
            source_sha256=graph_sha256,
            source_function_entry=source_entry,
            target_function_entry=target_entry,
            view="exact-only",
            max_hops=4,
            cfg_index=cfg_index,
            cfg_sha256=cfg_sha256,
        )
        _write(output_dir / filename, _jsonl_bytes(result))

    field_result = query_graphs(
        graphs,
        source_sha256=graph_sha256,
        view="exploratory",
        kinds=["field"],
        field_offsets=TOUCH_FIELDS,
    )
    _write(output_dir / "hit-area-field-query.jsonl", _jsonl_bytes(field_result))
    node_kinds = {node["id"]: node["kind"] for node in graphs[0]["nodes"]}
    joined_fields = sum(
        edge["relation"] == "has_field" and node_kinds[edge["to"]] == "field"
        for edge in graphs[0]["edges"]
    )
    print(
        f"functions={len(effects)} graph_nodes={len(graphs[0]['nodes'])} "
        f"graph_edges={len(graphs[0]['edges'])} field_to_type_joins={joined_fields}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    rebuild(args.output_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
