"""Validation shared by consumers of Ghidra indirect-call sidecars."""
from __future__ import annotations

import re
from typing import Any

FORMAT_V1 = "REVENGINSTR.GhidraIndirectCallEvidence/1"
FORMAT_V2 = "REVENGINSTR.GhidraIndirectCallEvidence/2"
FORMAT_V3 = "REVENGINSTR.GhidraIndirectCallEvidence/3"
FORMAT_V4 = "REVENGINSTR.GhidraIndirectCallEvidence/4"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FIELDS_V1 = {
    "format", "program", "requested", "function_entry", "call_address", "call_time",
    "target", "target_expression", "arg_count",
}
_FIELDS_V2 = _FIELDS_V1 | {"program_sha256", "architecture"}
_FIELDS_V3 = _FIELDS_V2 | {"target_resolution"}
_FIELDS_V4 = _FIELDS_V3 | {"parameter_roots"}


def validate_row(
    row: Any,
    where: str,
    *,
    program_id: str | None = None,
    program_sha256: str | None = None,
    expected_architecture: dict[str, Any] | None = None,
) -> str:
    """Validate one exact v1/v2 record and return its source format."""
    if not isinstance(row, dict):
        raise ValueError(f"{where}: indirect-call evidence must be an object")
    source_format = row.get("format")
    if source_format == FORMAT_V1:
        expected = _FIELDS_V1
    elif source_format == FORMAT_V2:
        expected = _FIELDS_V2
    elif source_format == FORMAT_V3:
        expected = _FIELDS_V3
    elif source_format == FORMAT_V4:
        expected = _FIELDS_V4
    else:
        raise ValueError(f"{where}: unsupported indirect-call evidence format")
    if set(row) != expected:
        raise ValueError(f"{where}: invalid {source_format} fields")
    for field in ("program", "requested", "function_entry", "call_address", "target", "target_expression"):
        if not isinstance(row[field], str) or not row[field]:
            raise ValueError(f"{where}: {field} must be a non-empty string")
    for field in ("call_time", "arg_count"):
        if type(row[field]) is not int or row[field] < 0:
            raise ValueError(f"{where}: {field} must be a non-negative integer")
    if program_id is not None and row["program"] != program_id:
        raise ValueError(f"{where}: program does not match {program_id!r}")
    if source_format in {FORMAT_V2, FORMAT_V3, FORMAT_V4}:
        digest = row["program_sha256"]
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise ValueError(f"{where}: invalid program_sha256")
        current_architecture = row["architecture"]
        if not isinstance(current_architecture, dict) or set(current_architecture) != {
            "language_id", "pointer_width_bytes", "endianness",
        }:
            raise ValueError(f"{where}: invalid architecture")
        if not isinstance(current_architecture["language_id"], str) or not current_architecture["language_id"]:
            raise ValueError(f"{where}: invalid architecture language_id")
        if type(current_architecture["pointer_width_bytes"]) is not int or current_architecture["pointer_width_bytes"] < 1:
            raise ValueError(f"{where}: invalid architecture pointer_width_bytes")
        if not isinstance(current_architecture["endianness"], str) or current_architecture["endianness"] not in ("little", "big"):
            raise ValueError(f"{where}: invalid architecture endianness")
        if program_sha256 is not None and digest != program_sha256:
            raise ValueError(f"{where}: program_sha256 does not match the expected binary")
        if expected_architecture is not None and current_architecture != expected_architecture:
            raise ValueError(f"{where}: architecture does not match the expected program")
    if source_format in {FORMAT_V3, FORMAT_V4}:
        resolution = row["target_resolution"]
        if not isinstance(resolution, dict) or set(resolution) != {"status", "slot_address", "function_entry"}:
            raise ValueError(f"{where}: invalid target_resolution")
        status = resolution["status"]
        slot = resolution["slot_address"]
        function_entry = resolution["function_entry"]
        if status not in {
            "resolved_static_function_pointer", "resolved_constant_function", "non_function_target",
            "unreadable_pointer", "unsupported_target_expression",
        }:
            raise ValueError(f"{where}: invalid target-resolution status")
        for name, address in (("slot_address", slot), ("function_entry", function_entry)):
            if address is not None and (not isinstance(address, str) or not re.fullmatch(r"0x[0-9a-fA-F]+", address)):
                raise ValueError(f"{where}: invalid target_resolution {name}")
        if status == "resolved_static_function_pointer" and (slot is None or function_entry is None):
            raise ValueError(f"{where}: resolved static function pointer lacks its slot or function entry")
        if status == "resolved_constant_function" and (slot is not None or function_entry is None):
            raise ValueError(f"{where}: resolved constant target has invalid slot/function entry")
        if status not in {"resolved_static_function_pointer", "resolved_constant_function"} and function_entry is not None:
            raise ValueError(f"{where}: unresolved target must not name a function entry")
    if source_format == FORMAT_V4:
        roots = row["parameter_roots"]
        if not isinstance(roots, list):
            raise ValueError(f"{where}: parameter_roots must be an array")
        if roots and row["target_resolution"]["function_entry"] is None:
            raise ValueError(f"{where}: unresolved target cannot have parameter roots")
        seen_indices = set()
        for root in roots:
            if not isinstance(root, dict) or set(root) != {
                "parameter_index", "caller_parameter_index", "argument_token",
            }:
                raise ValueError(f"{where}: invalid parameter root")
            for field in ("parameter_index", "caller_parameter_index"):
                if type(root[field]) is not int or root[field] < 0:
                    raise ValueError(f"{where}: invalid parameter root {field}")
            if root["parameter_index"] >= row["arg_count"]:
                raise ValueError(f"{where}: parameter root exceeds call argument count")
            if root["parameter_index"] in seen_indices:
                raise ValueError(f"{where}: duplicate parameter root index")
            seen_indices.add(root["parameter_index"])
            if not isinstance(root["argument_token"], str) or not root["argument_token"]:
                raise ValueError(f"{where}: invalid parameter root argument_token")
    return source_format
