"""Group evidence-backed effects into compact, machine-readable function summaries."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

FORMAT_V1 = "REVENGINSTR.FunctionSummary/1"
FORMAT_V2 = "REVENGINSTR.FunctionSummary/2"
FORMAT = FORMAT_V1
EFFECT_FORMAT_V1 = "REVENGINSTR.FunctionEffectIR/1"
EFFECT_FORMAT_V2 = "REVENGINSTR.FunctionEffectIR/2"
EFFECT_FORMAT = EFFECT_FORMAT_V1
_EFFECT_ID = re.compile(r"[0-9a-f]{64}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_OFFSET = re.compile(r"-?0x[0-9a-f]+\Z")
_KINDS = {
    "parameter_field_read": "derived_structural",
    "parameter_field_write": "derived_structural",
    "direct_call": "exact_static",
    "indirect_call": "exact_static",
    "return_op": "exact_static",
    "memory_read": "exact_static",
    "memory_write": "exact_static",
}
_OPCODES = {
    "parameter_field_read": "LOAD",
    "parameter_field_write": "STORE",
    "direct_call": "CALL",
    "indirect_call": "CALLIND",
    "return_op": "RETURN",
    "memory_read": "LOAD",
    "memory_write": "STORE",
}
_SOURCE_FORMATS = {
    "REVENGINSTR.GhidraParameterStoreField/1",
    "REVENGINSTR.GhidraParameterLoadField/1",
    "REVENGINSTR.GhidraFunctionPcodeFlow/1",
}
_SOURCE_FORMAT_BY_KIND = {
    "parameter_field_read": "REVENGINSTR.GhidraParameterLoadField/1",
    "parameter_field_write": "REVENGINSTR.GhidraParameterStoreField/1",
    "direct_call": "REVENGINSTR.GhidraFunctionPcodeFlow/1",
    "indirect_call": "REVENGINSTR.GhidraFunctionPcodeFlow/1",
    "return_op": "REVENGINSTR.GhidraFunctionPcodeFlow/1",
    "memory_read": "REVENGINSTR.GhidraFunctionPcodeFlow/1",
    "memory_write": "REVENGINSTR.GhidraFunctionPcodeFlow/1",
}
_EFFECT_FIELDS = {
    "effect_id", "kind", "operation_address", "operation_time", "opcode",
    "parameter_index", "field_offset", "value_size", "value_token",
    "source_parameter_index", "target_entry", "target_name", "inputs",
    "evidence_class", "provenance",
}


def _validate_effect_ir(records: list[dict[str, Any]], source_sha256: str) -> str:
    if not isinstance(source_sha256, str) or _SHA256.fullmatch(source_sha256) is None:
        raise ValueError("invalid Function Effect IR SHA-256")
    seen_functions: set[tuple[str, str]] = set()
    seen_effects: set[str] = set()
    effect_format: str | None = None
    for record_index, record in enumerate(records, 1):
        where = f"Function Effect IR record {record_index}"
        if (
            not isinstance(record, dict)
            or set(record) != {"format", "program_id", "function_entry", "effects"}
        ):
            raise ValueError(f"{where}: unexpected format or fields")
        record_format = record["format"]
        if not isinstance(record_format, str) or record_format not in {EFFECT_FORMAT_V1, EFFECT_FORMAT_V2}:
            raise ValueError(f"{where}: unexpected format or fields")
        if effect_format is not None and effect_format != record_format:
            raise ValueError(f"{where}: mixed Function Effect IR versions")
        effect_format = record_format
        program_id, function_entry = record["program_id"], record["function_entry"]
        if not isinstance(program_id, str) or not program_id or not isinstance(function_entry, str) or not function_entry:
            raise ValueError(f"{where}: invalid function identity")
        function_key = (program_id, function_entry)
        if function_key in seen_functions:
            raise ValueError(f"{where}: duplicate function identity")
        seen_functions.add(function_key)
        if not isinstance(record["effects"], list) or not record["effects"]:
            raise ValueError(f"{where}: effects must be a non-empty array")
        for effect_index, effect in enumerate(record["effects"], 1):
            effect_where = f"{where} effect {effect_index}"
            if not isinstance(effect, dict) or set(effect) != _EFFECT_FIELDS:
                raise ValueError(f"{effect_where}: unexpected fields")
            effect_id = effect["effect_id"]
            kind = effect["kind"]
            if (
                not isinstance(effect_id, str) or _EFFECT_ID.fullmatch(effect_id) is None
                or effect_id in seen_effects
            ):
                raise ValueError(f"{effect_where}: invalid or duplicate effect id")
            seen_effects.add(effect_id)
            if (
                not isinstance(kind, str) or kind not in _KINDS
                or effect["evidence_class"] != _KINDS[kind]
                or effect["opcode"] != _OPCODES[kind]
            ):
                raise ValueError(f"{effect_where}: unsupported kind, opcode, or evidence class")
            if record_format == EFFECT_FORMAT_V1 and kind in {"memory_read", "memory_write"}:
                raise ValueError(f"{effect_where}: generic memory effects require FunctionEffectIR/2")
            if not isinstance(effect["operation_address"], str) or not effect["operation_address"]:
                raise ValueError(f"{effect_where}: invalid operation address")
            operation_time = effect["operation_time"]
            if operation_time is not None and (
                not isinstance(operation_time, int) or isinstance(operation_time, bool) or operation_time < 0
            ):
                raise ValueError(f"{effect_where}: invalid operation time")
            if not isinstance(effect["inputs"], list) or any(not isinstance(token, str) or not token for token in effect["inputs"]):
                raise ValueError(f"{effect_where}: invalid inputs")
            provenance = effect["provenance"]
            if (
                not isinstance(provenance, dict)
                or set(provenance) != {"source_format", "artifact_sha256", "record_index"}
                or not isinstance(provenance["source_format"], str)
                or provenance["source_format"] not in _SOURCE_FORMATS
                or not isinstance(provenance["artifact_sha256"], str)
                or _SHA256.fullmatch(provenance["artifact_sha256"]) is None
                or not isinstance(provenance["record_index"], int)
                or isinstance(provenance["record_index"], bool)
                or provenance["record_index"] < 1
            ):
                raise ValueError(f"{effect_where}: invalid provenance")
            if provenance["source_format"] != _SOURCE_FORMAT_BY_KIND[kind]:
                raise ValueError(f"{effect_where}: source format does not match effect kind")
            expected_id = hashlib.sha256(
                f"{provenance['source_format']}\0{provenance['artifact_sha256']}\0{provenance['record_index']}".encode("utf-8")
            ).hexdigest()
            if effect_id != expected_id:
                raise ValueError(f"{effect_where}: effect id does not match provenance")
            _attributes(effect, effect_where)
    return effect_format or EFFECT_FORMAT_V1


def validate_function_effect_ir(records: list[dict[str, Any]], source_sha256: str) -> None:
    """Validate a FunctionEffectIR population and its pinned source digest."""
    _validate_effect_ir(records, source_sha256)


def _attributes(effect: dict[str, Any], where: str) -> dict[str, Any]:
    kind = effect["kind"]
    nullable = ("parameter_index", "field_offset", "value_size", "value_token", "source_parameter_index", "target_entry", "target_name")
    if any(key not in effect for key in nullable):
        raise ValueError(f"{where}: missing structural fields")
    if kind in {"parameter_field_read", "parameter_field_write"}:
        if kind == "parameter_field_read" and (
            effect["source_parameter_index"] is not None or effect["target_entry"] is not None
            or effect["target_name"] is not None or not isinstance(effect["value_token"], str)
            or not effect["value_token"]
        ):
            raise ValueError(f"{where}: invalid field-read attributes")
        if kind == "parameter_field_write" and (
            effect["target_entry"] is not None or effect["target_name"] is not None
            or effect["value_token"] is not None
        ):
            raise ValueError(f"{where}: invalid field-write attributes")
        parameter = effect["parameter_index"]
        offset = effect["field_offset"]
        size = effect["value_size"]
        if not isinstance(parameter, int) or isinstance(parameter, bool) or parameter < 0:
            raise ValueError(f"{where}: invalid parameter index")
        if not isinstance(offset, str) or _OFFSET.fullmatch(offset) is None:
            raise ValueError(f"{where}: invalid field offset")
        if (
            (kind == "parameter_field_read" and not isinstance(size, int))
            or (size is not None and (not isinstance(size, int) or isinstance(size, bool) or size < 0))
        ):
            raise ValueError(f"{where}: invalid value size")
        attrs = {"parameter_index": parameter, "field_offset": offset}
        if size is not None:
            attrs["value_size"] = size
        if kind == "parameter_field_write":
            source_parameter = effect["source_parameter_index"]
            if not isinstance(source_parameter, int) or isinstance(source_parameter, bool) or source_parameter < 0:
                raise ValueError(f"{where}: invalid source parameter index")
            attrs["source_parameter_index"] = source_parameter
        return attrs
    if kind in {"direct_call", "indirect_call"}:
        if any(effect[key] is not None for key in ("parameter_index", "field_offset", "value_size", "value_token", "source_parameter_index")):
            raise ValueError(f"{where}: invalid call attributes")
        if any(not isinstance(effect[key], str) or not effect[key] for key in ("target_entry", "target_name")):
            raise ValueError(f"{where}: invalid call target")
        return {
            "target_entry": None if effect["target_entry"] == "-" else effect["target_entry"],
            "target_name": None if effect["target_name"] == "-" else effect["target_name"],
        }
    if kind in {"memory_read", "memory_write"}:
        if any(effect[key] is not None for key in (
            "parameter_index", "field_offset", "value_size", "source_parameter_index",
            "target_entry", "target_name",
        )):
            raise ValueError(f"{where}: invalid generic memory attributes")
        value_token = effect["value_token"]
        if kind == "memory_read" and value_token is not None and (
            not isinstance(value_token, str) or not value_token
        ):
            raise ValueError(f"{where}: invalid memory-read output token")
        if kind == "memory_write" and value_token is not None:
            raise ValueError(f"{where}: invalid memory-write value token")
        return {}
    if any(effect[key] is not None for key in nullable):
        raise ValueError(f"{where}: invalid return attributes")
    return {}


def build_function_summaries(
    records: list[dict[str, Any]], *, source_sha256: str
) -> list[dict[str, Any]]:
    """Aggregate equivalent Effect IR facts without adding semantic claims."""
    effect_format = _validate_effect_ir(records, source_sha256)
    summary_format = FORMAT_V2 if effect_format == EFFECT_FORMAT_V2 else FORMAT_V1
    summaries: list[dict[str, Any]] = []
    for record in sorted(records, key=lambda row: (row["program_id"], row["function_entry"])):
        grouped: dict[str, dict[str, Any]] = {}
        for effect in record["effects"]:
            where = f"effect {effect['effect_id']}"
            attributes = _attributes(effect, where)
            key = json.dumps(
                [effect["kind"], effect["evidence_class"], attributes],
                sort_keys=True, separators=(",", ":"),
            )
            claim = grouped.setdefault(key, {
                "kind": effect["kind"],
                "evidence_class": effect["evidence_class"],
                "attributes": attributes,
                "support": [],
            })
            claim["support"].append({
                "effect_id": effect["effect_id"],
                "provenance": effect["provenance"],
            })
        claims = sorted(
            grouped.values(),
            key=lambda claim: (
                claim["kind"], json.dumps(claim["attributes"], sort_keys=True, separators=(",", ":")),
                claim["evidence_class"],
            ),
        )
        for claim in claims:
            claim["support"].sort(key=lambda item: item["effect_id"])
        summaries.append({
            "format": summary_format,
            "program_id": record["program_id"],
            "function_entry": record["function_entry"],
            "source_effect_ir_sha256": source_sha256,
            "claims": claims,
        })
    return summaries


def _read_jsonl(path: Path) -> tuple[str, list[dict[str, Any]]]:
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"{path}: input must be UTF-8") from error
    records = []
    for line_no, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            raise ValueError(f"{path}:{line_no}: blank JSONL record")
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"{path}:{line_no}: invalid JSON") from error
        if not isinstance(record, dict):
            raise ValueError(f"{path}:{line_no}: expected object")
        records.append(record)
    return hashlib.sha256(raw).hexdigest(), records


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("function_effect_ir", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    source_sha256, records = _read_jsonl(args.function_effect_ir)
    summaries = build_function_summaries(records, source_sha256=source_sha256)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for summary in summaries:
            handle.write(json.dumps(summary, sort_keys=True) + "\n")
    print("functions:", len(summaries))
    print("claims:", sum(len(summary["claims"]) for summary in summaries))
    print("output:", args.output)
    return 0
