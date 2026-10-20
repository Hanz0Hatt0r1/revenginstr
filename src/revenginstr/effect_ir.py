"""Project selected structural evidence into a provenance-linked function IR."""
from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

FORMAT_V1 = "REVENGINSTR.FunctionEffectIR/1"
FORMAT_V2 = "REVENGINSTR.FunctionEffectIR/2"
FORMAT = FORMAT_V1
STORE_FORMAT = "REVENGINSTR.GhidraParameterStoreField/1"
LOAD_FORMAT = "REVENGINSTR.GhidraParameterLoadField/1"
PCODE_FORMAT = "REVENGINSTR.GhidraFunctionPcodeFlow/1"
MEMORY_STORE_FORMAT = "REVENGINSTR.GhidraMemoryStoreAccess/1"
DEFAULT_MAX_EFFECTS = 100_000

_STORE_HEADER = (
    "format", "function_entry", "function_name", "store_address", "store_time",
    "destination_parameter_index", "destination_offset", "destination_pattern",
    "source_parameter_index", "value_size", "status",
)
_LOAD_HEADER = (
    "format", "function_entry", "function_name", "load_address", "load_time",
    "base_parameter_index", "field_offset", "address_pattern", "value_size",
    "value_token", "status",
)
_PCODE_HEADER = (
    "function_entry", "op_address", "op_time", "opcode", "output", "inputs",
    "callee_entry", "callee_name",
)
_OFFSET = re.compile(r"-?0x[0-9a-f]+\Z")
_PCODE_EFFECT_KINDS = {
    "CALL": "direct_call",
    "CALLIND": "indirect_call",
    "RETURN": "return_op",
    "LOAD": "memory_read",
    "STORE": "memory_write",
}
_MEMORY_STORE_FIELDS = {
    "format", "program_id", "function_entry", "address", "time", "opcode",
    "memory_space", "memory_physical_space", "memory_width_bytes",
    "memory_pointer_width_bytes", "memory_space_size_bits",
    "memory_addressable_unit_bytes", "pointer_token", "root_parameter_index",
    "offset_bytes", "location_status", "destination_pattern", "address_expression_ops",
}


def _read_tsv(path: Path, expected_header: tuple[str, ...]) -> tuple[str, list[dict[str, str]]]:
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"{path}: input must be UTF-8") from error
    reader = csv.DictReader(io.StringIO(text, newline=""), delimiter="\t", strict=True)
    if tuple(reader.fieldnames or ()) != expected_header:
        raise ValueError(f"{path}: unexpected TSV header")
    rows: list[dict[str, str]] = []
    for record_index, row in enumerate(reader, 1):
        if None in row or any(value is None for value in row.values()):
            raise ValueError(f"{path}: malformed TSV record {record_index}")
        rows.append(row)
    return hashlib.sha256(raw).hexdigest(), rows


def _required(row: dict[str, str], field: str, where: str) -> str:
    value = row.get(field, "")
    if not value or value == "-":
        raise ValueError(f"{where}: missing {field}")
    return value


def _decimal(value: str, field: str, where: str, *, optional: bool = False) -> int | None:
    if optional and value == "-":
        return None
    if not value.isascii() or not value.isdecimal():
        raise ValueError(f"{where}: invalid {field}")
    return int(value)


def _effect_id(source_format: str, artifact_sha256: str, record_index: int) -> str:
    identity = f"{source_format}\0{artifact_sha256}\0{record_index}".encode("utf-8")
    return hashlib.sha256(identity).hexdigest()


def _provenance(source_format: str, artifact_sha256: str, record_index: int) -> dict[str, Any]:
    return {
        "source_format": source_format,
        "artifact_sha256": artifact_sha256,
        "record_index": record_index,
    }


def _base_effect(
    *,
    source_format: str,
    artifact_sha256: str,
    record_index: int,
    kind: str,
    address: str,
    time: int | None,
    opcode: str,
    evidence_class: str,
) -> dict[str, Any]:
    return {
        "effect_id": _effect_id(source_format, artifact_sha256, record_index),
        "kind": kind,
        "operation_address": address,
        "operation_time": time,
        "opcode": opcode,
        "parameter_index": None,
        "field_offset": None,
        "value_size": None,
        "value_token": None,
        "source_parameter_index": None,
        "target_entry": None,
        "target_name": None,
        "inputs": [],
        "evidence_class": evidence_class,
        "provenance": _provenance(source_format, artifact_sha256, record_index),
    }


def _read_memory_store_access(path: Path, *, program_id: str) -> tuple[str, list[dict[str, Any]]]:
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"{path}: input must be UTF-8") from error
    rows = []
    for record_index, line in enumerate(text.splitlines(), 1):
        where = f"{path}: memory-store record {record_index}"
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"{where}: invalid JSON") from error
        if not isinstance(row, dict) or set(row) != _MEMORY_STORE_FIELDS:
            raise ValueError(f"{where}: malformed GhidraMemoryStoreAccess/1 fields")
        if row.get("format") != MEMORY_STORE_FORMAT or row.get("program_id") != program_id:
            raise ValueError(f"{where}: format or program_id does not match the selected program")
        if any(not isinstance(row.get(key), str) or not row[key] for key in (
            "function_entry", "address", "opcode", "pointer_token", "destination_pattern",
        )):
            raise ValueError(f"{where}: invalid operation or pointer identity")
        if row["opcode"] != "STORE" or type(row.get("time")) is not int or row["time"] < 0:
            raise ValueError(f"{where}: expected an exact STORE operation key")
        for key in ("memory_space", "memory_physical_space"):
            value = row.get(key)
            if value is not None and (not isinstance(value, str) or not value):
                raise ValueError(f"{where}: invalid {key}")
        for key in (
            "memory_width_bytes", "memory_pointer_width_bytes",
            "memory_space_size_bits", "memory_addressable_unit_bytes",
        ):
            value = row.get(key)
            if value is not None and (type(value) is not int or value < 1):
                raise ValueError(f"{where}: invalid {key}")
        root_parameter_index = row.get("root_parameter_index")
        if root_parameter_index is not None and (
            type(root_parameter_index) is not int or root_parameter_index < 0
        ):
            raise ValueError(f"{where}: invalid root_parameter_index")
        offset_bytes = row.get("offset_bytes")
        if offset_bytes is not None and type(offset_bytes) is not int:
            raise ValueError(f"{where}: invalid offset_bytes")
        if row.get("location_status") not in {"parameter_rooted_constant_offset", "unresolved"}:
            raise ValueError(f"{where}: invalid location_status")
        expression_ops = row.get("address_expression_ops")
        if not isinstance(expression_ops, list) or any(
            not isinstance(op, dict)
            or set(op) != {"address", "time", "opcode"}
            or not isinstance(op["address"], str) or not op["address"]
            or type(op["time"]) is not int or op["time"] < 0
            or not isinstance(op["opcode"], str) or not op["opcode"]
            for op in expression_ops
        ):
            raise ValueError(f"{where}: malformed address_expression_ops")
        if row["location_status"] == "parameter_rooted_constant_offset":
            if type(root_parameter_index) is not int:
                raise ValueError(f"{where}: invalid root_parameter_index")
            if type(offset_bytes) is not int:
                raise ValueError(f"{where}: invalid offset_bytes")
            for key in (
                "memory_space", "memory_width_bytes", "memory_pointer_width_bytes",
                "memory_space_size_bits", "memory_addressable_unit_bytes",
            ):
                value = row.get(key)
                if key == "memory_space":
                    valid = isinstance(value, str) and bool(value)
                else:
                    valid = type(value) is int and value >= 1
                if not valid:
                    raise ValueError(f"{where}: invalid {key}")
            row["_record_index"] = record_index
            rows.append(row)
    return hashlib.sha256(raw).hexdigest(), rows


def build_function_effect_ir(
    program_id: str,
    *,
    parameter_store_tsv: Path | None = None,
    parameter_load_tsv: Path | None = None,
    memory_store_access_jsonl: Path | None = None,
    pcode_flow_tsv: Path | None = None,
    include_generic_memory_ops: bool = False,
    max_effects: int = DEFAULT_MAX_EFFECTS,
) -> list[dict[str, Any]]:
    """Build function summaries from selected, schema-defined generic TSV inputs.

    This projection records structural operations only. It does not assign
    semantic roles or claim that a field store reaches a later field load.
    """
    if not program_id:
        raise ValueError("program_id must be non-empty")
    if max_effects < 1:
        raise ValueError("max_effects must be positive")
    if not any((parameter_store_tsv, parameter_load_tsv, memory_store_access_jsonl, pcode_flow_tsv)):
        raise ValueError("at least one input artifact is required")
    if include_generic_memory_ops and pcode_flow_tsv is None:
        raise ValueError("generic memory effects require P-code flow input")

    by_function: dict[str, list[dict[str, Any]]] = defaultdict(list)
    effect_count = 0

    def add(function_entry: str, effect: dict[str, Any]) -> None:
        nonlocal effect_count
        if effect_count >= max_effects:
            raise ValueError(f"function effect budget exceeded: {max_effects}")
        by_function[function_entry].append(effect)
        effect_count += 1

    if parameter_store_tsv is not None:
        artifact_sha256, rows = _read_tsv(parameter_store_tsv, _STORE_HEADER)
        for record_index, row in enumerate(rows, 1):
            where = f"parameter store record {record_index}"
            if row["format"] != STORE_FORMAT or row["status"] != "parameter_to_parameter_field":
                raise ValueError(f"{where}: unsupported format or status")
            function_entry = _required(row, "function_entry", where)
            address = _required(row, "store_address", where)
            effect = _base_effect(
                source_format=STORE_FORMAT, artifact_sha256=artifact_sha256,
                record_index=record_index, kind="parameter_field_write", address=address,
                time=_decimal(row["store_time"], "store_time", where, optional=True),
                opcode="STORE", evidence_class="derived_structural",
            )
            offset = row["destination_offset"]
            if _OFFSET.fullmatch(offset) is None:
                raise ValueError(f"{where}: invalid destination_offset")
            effect.update({
                "parameter_index": _decimal(row["destination_parameter_index"], "destination_parameter_index", where),
                "field_offset": offset,
                "value_size": _decimal(row["value_size"], "value_size", where, optional=True),
                "source_parameter_index": _decimal(row["source_parameter_index"], "source_parameter_index", where),
            })
            add(function_entry, effect)

    if parameter_load_tsv is not None:
        artifact_sha256, rows = _read_tsv(parameter_load_tsv, _LOAD_HEADER)
        for record_index, row in enumerate(rows, 1):
            where = f"parameter load record {record_index}"
            if row["format"] != LOAD_FORMAT or row["status"] != "parameter_field_load":
                raise ValueError(f"{where}: unsupported format or status")
            function_entry = _required(row, "function_entry", where)
            address = _required(row, "load_address", where)
            effect = _base_effect(
                source_format=LOAD_FORMAT, artifact_sha256=artifact_sha256,
                record_index=record_index, kind="parameter_field_read", address=address,
                time=_decimal(row["load_time"], "load_time", where, optional=True),
                opcode="LOAD", evidence_class="derived_structural",
            )
            offset = row["field_offset"]
            if _OFFSET.fullmatch(offset) is None:
                raise ValueError(f"{where}: invalid field_offset")
            effect.update({
                "parameter_index": _decimal(row["base_parameter_index"], "base_parameter_index", where),
                "field_offset": offset,
                "value_size": _decimal(row["value_size"], "value_size", where),
                "value_token": _required(row, "value_token", where),
            })
            add(function_entry, effect)

    if memory_store_access_jsonl is not None:
        artifact_sha256, rows = _read_memory_store_access(
            memory_store_access_jsonl, program_id=program_id,
        )
        for row in rows:
            effect = _base_effect(
                source_format=MEMORY_STORE_FORMAT,
                artifact_sha256=artifact_sha256,
                record_index=row["_record_index"],
                kind="parameter_field_write",
                address=row["address"],
                time=row["time"],
                opcode="STORE",
                evidence_class="derived_structural",
            )
            effect.update({
                "parameter_index": row["root_parameter_index"],
                "field_offset": hex(row["offset_bytes"]),
                "value_size": row["memory_width_bytes"],
            })
            add(row["function_entry"], effect)

    if pcode_flow_tsv is not None:
        artifact_sha256, rows = _read_tsv(pcode_flow_tsv, _PCODE_HEADER)
        for record_index, row in enumerate(rows, 1):
            where = f"P-code flow record {record_index}"
            function_entry = _required(row, "function_entry", where)
            opcode = _required(row, "opcode", where)
            address = _required(row, "op_address", where)
            operation_time = _decimal(row["op_time"], "op_time", where)
            kind = _PCODE_EFFECT_KINDS.get(opcode)
            if kind is None or (opcode in {"LOAD", "STORE"} and not include_generic_memory_ops):
                continue
            effect = _base_effect(
                source_format=PCODE_FORMAT, artifact_sha256=artifact_sha256,
                record_index=record_index, kind=kind, address=address,
                time=operation_time, opcode=opcode, evidence_class="exact_static",
            )
            inputs = row["inputs"]
            if not inputs:
                raise ValueError(f"{where}: missing inputs cell")
            effect["inputs"] = [] if inputs == "-" else inputs.split(";")
            if any(not token for token in effect["inputs"]):
                raise ValueError(f"{where}: malformed inputs cell")
            if opcode == "LOAD":
                output = row["output"]
                effect["value_token"] = None if output == "-" else _required(row, "output", where)
            if opcode in {"CALL", "CALLIND"}:
                for source_field, target_field in (
                    ("callee_entry", "target_entry"),
                    ("callee_name", "target_name"),
                ):
                    value = row[source_field]
                    effect[target_field] = "-" if value == "-" else _required(row, source_field, where)
            add(function_entry, effect)

    return [
        {
            "format": FORMAT_V2 if include_generic_memory_ops else FORMAT_V1,
            "program_id": program_id,
            "function_entry": function_entry,
            "effects": sorted(
                effects,
                key=lambda effect: (
                    effect["operation_address"],
                    -1 if effect["operation_time"] is None else effect["operation_time"],
                    effect["kind"],
                    effect["effect_id"],
                ),
            ),
        }
        for function_entry, effects in sorted(by_function.items())
    ]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--program-id", required=True, help="Opaque consumer join key for the selected program.")
    parser.add_argument("--parameter-stores", type=Path)
    parser.add_argument("--parameter-loads", type=Path)
    parser.add_argument(
        "--memory-store-access", type=Path,
        help="optional GhidraMemoryStoreAccess/1 JSONL; adds parameter-rooted constant-offset writes",
    )
    parser.add_argument("--pcode-flow", type=Path)
    parser.add_argument(
        "--include-generic-memory-ops", action="store_true",
        help="emit FunctionEffectIR/2 and include every P-code LOAD/STORE operation",
    )
    parser.add_argument("--max-effects", type=int, default=DEFAULT_MAX_EFFECTS)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    records = build_function_effect_ir(
        args.program_id,
        parameter_store_tsv=args.parameter_stores,
        parameter_load_tsv=args.parameter_loads,
        memory_store_access_jsonl=args.memory_store_access,
        pcode_flow_tsv=args.pcode_flow,
        include_generic_memory_ops=args.include_generic_memory_ops,
        max_effects=args.max_effects,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
    print("functions:", len(records))
    print("effects:", sum(len(record["effects"]) for record in records))
    print("output:", args.output)
    return 0
