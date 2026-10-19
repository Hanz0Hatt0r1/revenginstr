"""Build conservative function prototype hypotheses from Ghidra observations."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

DECOMPILER_FORMAT = "REVENGINSTR.GhidraDecompilerParameters/1"
CALL_FORMAT = "REVENGINSTR.DirectCallArgumentObservation/1"
FORMAT = "REVENGINSTR.FunctionPrototypeHypothesis/1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ADDRESS = re.compile(r"^(?:[A-Za-z_$][\w$]*:)?(?:0x)?[0-9a-fA-F]+$")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-JSON numeric constant {value}")


def _read_jsonl(path: Path) -> tuple[list[tuple[int, dict[str, Any]]], str]:
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"{path}: input is not valid UTF-8") from error
    rows: list[tuple[int, dict[str, Any]]] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(line, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
        except ValueError as error:
            raise ValueError(f"{path}:{line_no}: invalid JSON: {error}") from error
        if not isinstance(row, dict):
            raise ValueError(f"{path}:{line_no}: expected a JSON object")
        rows.append((line_no, row))
    return rows, digest


def _text(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{where}: expected a non-empty string")
    return value


def _address(value: Any, where: str) -> str:
    if not isinstance(value, str) or not _ADDRESS.fullmatch(value):
        raise ValueError(f"{where}: invalid address {value!r}")
    return value


def _sha(value: Any, where: str) -> str:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{where}: invalid SHA-256")
    return value


def _architecture(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"language_id", "pointer_width_bytes", "endianness"}:
        raise ValueError(f"{where}: invalid architecture fields")
    _text(value["language_id"], f"{where}: language_id")
    if type(value["pointer_width_bytes"]) is not int or value["pointer_width_bytes"] < 1:
        raise ValueError(f"{where}: invalid pointer_width_bytes")
    if not isinstance(value["endianness"], str) or value["endianness"] not in {"little", "big"}:
        raise ValueError(f"{where}: invalid endianness")
    return value


def _type_record(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"kind", "name", "path", "width_bytes"}:
        raise ValueError(f"{where}: invalid type record")
    if not isinstance(value["kind"], str) or value["kind"] not in {
        "void", "pointer", "aggregate", "scalar", "unknown",
    }:
        raise ValueError(f"{where}: invalid type kind")
    _text(value["name"], f"{where}: type name")
    _text(value["path"], f"{where}: type path")
    width = value["width_bytes"]
    if width is not None and (type(width) is not int or width < 1):
        raise ValueError(f"{where}: invalid type width")
    return value


def _read_decompiler(path: Path) -> tuple[dict[str, dict[str, Any]], str, str, str, dict[str, Any]]:
    rows, digest = _read_jsonl(path)
    functions: dict[str, dict[str, Any]] = {}
    metadata: tuple[str, str, dict[str, Any]] | None = None
    required = {
        "format", "plan_id", "program_id", "program_sha256", "architecture", "requested_entry",
        "function_entry", "name", "is_external", "status", "signature_source", "calling_convention",
        "has_varargs", "parameter_count", "parameters", "return_type", "return_storage", "error",
    }
    for line_no, row in rows:
        where = f"{path}:{line_no}"
        if set(row) != required or row.get("format") != DECOMPILER_FORMAT:
            raise ValueError(f"{where}: expected {DECOMPILER_FORMAT} with its exact fields")
        program_id = _text(row["program_id"], f"{where}: program_id")
        program_sha = _sha(row["program_sha256"], f"{where}: program_sha256")
        arch = _architecture(row["architecture"], f"{where}: architecture")
        current = (program_id, program_sha, arch)
        if metadata is None:
            metadata = current
        elif current != metadata:
            raise ValueError(f"{where}: decompiler records describe multiple program identities")
        entry = _address(row["function_entry"], f"{where}: function_entry")
        _text(row["plan_id"], f"{where}: plan_id")
        _text(row["name"], f"{where}: name")
        _text(row["signature_source"], f"{where}: signature_source")
        if row["calling_convention"] is not None and not isinstance(row["calling_convention"], str):
            raise ValueError(f"{where}: calling_convention must be string or null")
        if not isinstance(row["has_varargs"], bool) or not isinstance(row["is_external"], bool):
            raise ValueError(f"{where}: invalid boolean fields")
        if not isinstance(row["status"], str) or row["status"] not in {
            "complete", "external", "decompile_failed", "no_high_function", "prototype_unavailable",
        }:
            raise ValueError(f"{where}: invalid status")
        if row["is_external"] != (row["status"] == "external"):
            raise ValueError(f"{where}: external flag conflicts with status")
        params = row["parameters"]
        if not isinstance(params, list):
            raise ValueError(f"{where}: parameters must be an array")
        if row["status"] == "complete":
            if type(row["parameter_count"]) is not int or row["parameter_count"] != len(params):
                raise ValueError(f"{where}: parameter_count does not match parameters")
            for index, parameter in enumerate(params):
                if not isinstance(parameter, dict) or set(parameter) != {
                    "index", "name", "type", "storage", "is_this_pointer", "is_hidden_return", "is_type_locked",
                }:
                    raise ValueError(f"{where}: invalid parameter record {index}")
                if type(parameter["index"]) is not int or parameter["index"] != index:
                    raise ValueError(f"{where}: parameter indices must be contiguous")
                _type_record(parameter["type"], f"{where}: parameter {index}")
                if parameter["name"] is not None and not isinstance(parameter["name"], str):
                    raise ValueError(f"{where}: invalid parameter name {index}")
                if parameter["storage"] is not None and not isinstance(parameter["storage"], str):
                    raise ValueError(f"{where}: invalid parameter storage {index}")
                for field in ("is_this_pointer", "is_hidden_return", "is_type_locked"):
                    if not isinstance(parameter[field], bool):
                        raise ValueError(f"{where}: invalid parameter {field} at {index}")
            _type_record(row["return_type"], f"{where}: return type")
        elif row["parameter_count"] is not None or params or row["return_type"] is not None:
            raise ValueError(f"{where}: unavailable result must not claim parameter or return data")
        if entry in functions:
            raise ValueError(f"{where}: duplicate function entry {entry}")
        functions[entry] = {**row, "_record_index": line_no}
    if metadata is None:
        raise ValueError(f"{path}: decompiler input is empty")
    return functions, metadata[0], metadata[1], digest, metadata[2]


def _read_calls(path: Path, program_id: str, program_sha: str) -> tuple[list[dict[str, Any]], str]:
    rows, digest = _read_jsonl(path)
    calls = []
    required = {
        "format", "program_id", "program_sha256", "caller_entry", "callee_entry", "call_address",
        "call_time", "argument_count", "arguments", "evidence_ref",
    }
    seen = set()
    for line_no, row in rows:
        where = f"{path}:{line_no}"
        if set(row) != required or row.get("format") != CALL_FORMAT:
            raise ValueError(f"{where}: expected {CALL_FORMAT} with its exact fields")
        if row["program_id"] != program_id or row["program_sha256"] != program_sha:
            raise ValueError(f"{where}: call observations do not match decompiler program identity")
        caller = _address(row["caller_entry"], f"{where}: caller_entry")
        callee = _address(row["callee_entry"], f"{where}: callee_entry")
        site = _address(row["call_address"], f"{where}: call_address")
        if type(row["call_time"]) is not int or row["call_time"] < 0:
            raise ValueError(f"{where}: invalid call_time")
        count = row["argument_count"]
        args = row["arguments"]
        if type(count) is not int or count < 0 or not isinstance(args, list) or count != len(args):
            raise ValueError(f"{where}: invalid argument_count/arguments")
        for index, arg in enumerate(args):
            if not isinstance(arg, dict) or set(arg) != {"index", "value_token", "width_bytes"}:
                raise ValueError(f"{where}: invalid argument {index}")
            if type(arg["index"]) is not int or arg["index"] != index or type(arg["width_bytes"]) is not int or arg["width_bytes"] < 1:
                raise ValueError(f"{where}: invalid argument index/width at {index}")
            _text(arg["value_token"], f"{where}: argument {index} value_token")
        ref = row["evidence_ref"]
        if not isinstance(ref, dict) or set(ref) != {"artifact_sha256", "record_index", "source_format"}:
            raise ValueError(f"{where}: invalid evidence_ref")
        if ref["source_format"] != "REVENGINSTR.GhidraFunctionPcodeFlow/1":
            raise ValueError(f"{where}: unsupported call source format")
        _sha(ref["artifact_sha256"], f"{where}: source artifact sha")
        if type(ref["record_index"]) is not int or ref["record_index"] < 1:
            raise ValueError(f"{where}: invalid source record_index")
        identity = (caller, site, row["call_time"])
        if identity in seen:
            raise ValueError(f"{where}: duplicate call site {identity}")
        seen.add(identity)
        calls.append({**row, "_record_index": line_no})
    return calls, digest


def _evidence(digest: str, record_index: int, source_format: str) -> dict[str, Any]:
    return {"artifact_sha256": digest, "record_index": record_index, "source_format": source_format}


def _shape_kind(type_row: dict[str, Any], *, return_value: bool = False) -> str:
    kind = type_row["kind"]
    if kind == "void" and return_value:
        return "void"
    return kind if kind in {"pointer", "aggregate", "scalar"} else "unknown"


def infer_prototypes(decompiler_path: Path, calls_path: Path) -> list[dict[str, Any]]:
    """Create hash-pinned review hypotheses; call-site arity is only a constraint."""
    functions, program_id, program_sha, decompiler_sha, architecture = _read_decompiler(decompiler_path)
    calls, calls_sha = _read_calls(calls_path, program_id, program_sha)
    missing_callees = sorted({call["callee_entry"] for call in calls} - set(functions))
    if missing_callees:
        preview = ", ".join(missing_callees[:5])
        raise ValueError(f"decompiler plan omits {len(missing_callees)} observed callees: {preview}")

    calls_by_callee: dict[str, list[dict[str, Any]]] = {}
    for call in calls:
        calls_by_callee.setdefault(call["callee_entry"], []).append(call)
    results = []
    for entry, function in functions.items():
        source_ref = _evidence(decompiler_sha, function["_record_index"], DECOMPILER_FORMAT)
        observations = calls_by_callee.get(entry, [])
        call_refs = [
            _evidence(calls_sha, call["_record_index"], CALL_FORMAT)
            for call in observations
        ]
        if function["status"] != "complete":
            candidate = {
                "candidate_id": "decompiler-unavailable",
                "parameter_count": None,
                "calling_convention": None,
                "parameters": [],
                "return_value": {"kind": "unknown", "width_bytes": None},
                "receiver_parameter_index": None,
                "confidence": 0.1,
                "evidence_refs": [source_ref, *call_refs],
            }
            results.append({
                "format": FORMAT, "program_id": program_id, "program_sha256": program_sha,
                "architecture": architecture, "function_entry": entry, "status": "review",
                "candidates": [candidate], "conflicts": [],
            })
            continue

        params = function["parameters"]
        count = function["parameter_count"]
        receiver_indices = [parameter["index"] for parameter in params if parameter["is_this_pointer"]]
        parameter_shapes = [
            {"index": parameter["index"], "kind": _shape_kind(parameter["type"]),
             "width_bytes": parameter["type"]["width_bytes"]}
            for parameter in params
        ]
        return_row = function["return_type"]
        return_shape = {
            "kind": _shape_kind(return_row, return_value=True),
            "width_bytes": return_row["width_bytes"],
        }
        convention = function["calling_convention"]
        if convention is not None and convention.strip().lower() in {"", "unknown", "default"}:
            convention = None
        call_mismatches = [
            call for call in observations
            if (call["argument_count"] < count if function["has_varargs"] else call["argument_count"] != count)
        ]
        # Scores are deliberately bounded below evaluator high-confidence thresholds.
        # Call-site arity adds at most modest support and never supplies types.
        corroborating_callers = len({call["caller_entry"] for call in observations if call not in call_mismatches})
        confidence = min(0.7, 0.5 + 0.05 * min(corroborating_callers, 4))
        refs = [source_ref, *call_refs]
        candidate = {
            "candidate_id": "ghidra-high-pcode-parameters",
            # Schema /1 has no varargs bit. Null total count preserves the known
            # fixed prefix without misrepresenting it as an exact total arity.
            "parameter_count": None if function["has_varargs"] else count,
            "calling_convention": convention,
            "parameters": parameter_shapes,
            "return_value": return_shape,
            "receiver_parameter_index": receiver_indices[0] if len(receiver_indices) == 1 else None,
            "confidence": confidence,
            "evidence_refs": refs,
        }
        conflicts = []
        status = "review"
        if len(receiver_indices) > 1:
            conflicts.append({"reason": "receiver_identity_conflict", "evidence_refs": [source_ref]})
        if call_mismatches:
            mismatch_refs = [
                _evidence(calls_sha, call["_record_index"], CALL_FORMAT)
                for call in call_mismatches
            ]
            conflicts.append({
                "reason": "incompatible_parameter_counts",
                "evidence_refs": [source_ref, *mismatch_refs],
            })
        if conflicts:
            status = "conflicted"
        results.append({
            "format": FORMAT, "program_id": program_id, "program_sha256": program_sha,
            "architecture": architecture, "function_entry": entry, "status": status,
            "candidates": [candidate], "conflicts": conflicts,
        })
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("decompiler_parameters", type=Path, help="GhidraDecompilerParameters/1 JSONL")
    parser.add_argument("call_observations", type=Path, help="DirectCallArgumentObservation/1 JSONL")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.output.resolve() in {args.decompiler_parameters.resolve(), args.call_observations.resolve()}:
        print("error: output path must differ from both input paths", file=sys.stderr)
        return 2
    try:
        rows = infer_prototypes(args.decompiler_parameters, args.call_observations)
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_name(args.output.name + ".tmp")
    try:
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            for row in rows:
                handle.write(json.dumps(row, sort_keys=True, allow_nan=False) + "\n")
        temporary.replace(args.output)
    finally:
        temporary.unlink(missing_ok=True)
    print("format:", FORMAT)
    print("functions:", len(rows))
    print("review:", sum(row["status"] == "review" for row in rows))
    print("conflicted:", sum(row["status"] == "conflicted" for row in rows))
    print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
