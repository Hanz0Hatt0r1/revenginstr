"""Check stored Ghidra prototype arity against resolved direct call sites."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterator

OBSERVATION_FORMAT = "REVENGINSTR.DirectCallArgumentObservation/1"
PROTOTYPE_FORMAT = "REVENGINSTR.GhidraFunctionPrototype/1"
FORMAT = "REVENGINSTR.FunctionPrototypeCallsiteCompatibility/1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ADDRESS = re.compile(r"^(?:[A-Za-z_$][\w$]*:)?(?:0x)?[0-9a-fA-F]+$")
_PROTOTYPE_FIELDS = {
    "format", "plan_id", "program_id", "program_sha256", "architecture",
    "requested_entry", "resolved_entry", "name", "qualified_name", "is_external",
    "signature_source", "calling_convention", "has_varargs", "parameter_count",
    "parameters", "return_type", "signature",
}
_OBSERVATION_FIELDS = {
    "format", "program_id", "program_sha256", "caller_entry", "callee_entry", "call_address",
    "call_time", "argument_count", "arguments", "evidence_ref",
}
_ARGUMENT_FIELDS = {"index", "value_token", "width_bytes"}
_EVIDENCE_FIELDS = {"artifact_sha256", "record_index", "source_format"}


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-JSON numeric constant {value}")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _read_jsonl(path: Path) -> Iterator[tuple[int, dict[str, Any]]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        for line_no, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            try:
                row = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
            except ValueError as error:
                raise ValueError(f"{path}:{line_no}: invalid JSON: {error}") from error
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_no}: expected a JSON object")
            yield line_no, row


def _text(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{where}: expected a non-empty string")
    return value


def _address(value: Any, where: str) -> str:
    if not isinstance(value, str) or not _ADDRESS.fullmatch(value):
        raise ValueError(f"{where}: invalid address {value!r}")
    return value


def _architecture(value: Any, where: str) -> dict[str, Any]:
    expected = {"language_id", "pointer_width_bytes", "endianness"}
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError(f"{where}: invalid architecture fields")
    _text(value["language_id"], where)
    if type(value["pointer_width_bytes"]) is not int or value["pointer_width_bytes"] < 1:
        raise ValueError(f"{where}: invalid pointer_width_bytes")
    if not isinstance(value["endianness"], str) or value["endianness"] not in {"little", "big"}:
        raise ValueError(f"{where}: invalid endianness")
    return value


def _read_prototypes(path: Path) -> tuple[dict[str, dict[str, Any]], str, str, dict[str, Any], str]:
    digest = _sha256(path)
    prototypes: dict[str, dict[str, Any]] = {}
    program_id = program_sha256 = None
    architecture = None
    for line_no, row in _read_jsonl(path):
        where = f"{path}:{line_no}"
        if set(row) != _PROTOTYPE_FIELDS or row.get("format") != PROTOTYPE_FORMAT:
            raise ValueError(f"{where}: expected {PROTOTYPE_FORMAT}")
        current_program = _text(row.get("program_id"), f"{where}: program_id")
        current_sha = row.get("program_sha256")
        if not isinstance(current_sha, str) or not _SHA256.fullmatch(current_sha):
            raise ValueError(f"{where}: invalid program_sha256")
        current_architecture = _architecture(row.get("architecture"), f"{where}: architecture")
        if program_id is None:
            program_id, program_sha256, architecture = current_program, current_sha, current_architecture
        elif (current_program, current_sha, current_architecture) != (program_id, program_sha256, architecture):
            raise ValueError(f"{where}: prototype rows do not describe one pinned program")
        entry = _address(row.get("resolved_entry"), f"{where}: resolved_entry")
        count = row.get("parameter_count")
        parameters = row.get("parameters")
        varargs = row.get("has_varargs")
        if type(count) is not int or count < 0 or not isinstance(parameters, list) or len(parameters) != count:
            raise ValueError(f"{where}: invalid parameter_count/parameters")
        if not isinstance(varargs, bool):
            raise ValueError(f"{where}: has_varargs must be boolean")
        source = _text(row.get("signature_source"), f"{where}: signature_source")
        if entry in prototypes:
            raise ValueError(f"{where}: duplicate prototype for {entry}")
        prototypes[entry] = {
            "parameter_count": count,
            "has_varargs": varargs,
            "signature_source": source,
            "record_index": line_no,
        }
    if program_id is None or program_sha256 is None or architecture is None:
        raise ValueError(f"{path}: prototype snapshot file is empty")
    return prototypes, program_id, program_sha256, architecture, digest


def _read_observations(path: Path) -> tuple[list[dict[str, Any]], str, str | None, str | None]:
    digest = _sha256(path)
    observations = []
    program_id = None
    program_sha256 = None
    seen_sites: set[tuple[str, str, int]] = set()
    for line_no, row in _read_jsonl(path):
        where = f"{path}:{line_no}"
        if set(row) != _OBSERVATION_FIELDS or row.get("format") != OBSERVATION_FORMAT:
            raise ValueError(f"{where}: expected {OBSERVATION_FORMAT}")
        current_program = _text(row.get("program_id"), f"{where}: program_id")
        current_sha = row.get("program_sha256")
        if not isinstance(current_sha, str) or not _SHA256.fullmatch(current_sha):
            raise ValueError(f"{where}: invalid program_sha256")
        if program_id is None:
            program_id, program_sha256 = current_program, current_sha
        elif (program_id, program_sha256) != (current_program, current_sha):
            raise ValueError(f"{where}: observations contain multiple program identities")
        caller = _address(row.get("caller_entry"), f"{where}: caller_entry")
        callee = _address(row.get("callee_entry"), f"{where}: callee_entry")
        call_address = _address(row.get("call_address"), f"{where}: call_address")
        call_time = row.get("call_time")
        argument_count = row.get("argument_count")
        arguments = row.get("arguments")
        if type(call_time) is not int or call_time < 0:
            raise ValueError(f"{where}: invalid call_time")
        if type(argument_count) is not int or argument_count < 0 or not isinstance(arguments, list):
            raise ValueError(f"{where}: invalid argument_count/arguments")
        if argument_count != len(arguments):
            raise ValueError(f"{where}: argument_count does not match arguments")
        for index, argument in enumerate(arguments):
            if not isinstance(argument, dict) or set(argument) != _ARGUMENT_FIELDS:
                raise ValueError(f"{where}: invalid argument {index}")
            if argument["index"] != index or type(argument["index"]) is not int:
                raise ValueError(f"{where}: argument indices must be contiguous")
            _text(argument["value_token"], f"{where}: argument {index} value_token")
            if type(argument["width_bytes"]) is not int or argument["width_bytes"] < 1:
                raise ValueError(f"{where}: invalid argument {index} width_bytes")
        ref = row.get("evidence_ref")
        if not isinstance(ref, dict) or set(ref) != _EVIDENCE_FIELDS:
            raise ValueError(f"{where}: invalid evidence_ref")
        if not isinstance(ref["artifact_sha256"], str) or not _SHA256.fullmatch(ref["artifact_sha256"]):
            raise ValueError(f"{where}: invalid source artifact_sha256")
        if type(ref["record_index"]) is not int or ref["record_index"] < 1:
            raise ValueError(f"{where}: invalid source record_index")
        if ref["source_format"] != "REVENGINSTR.GhidraFunctionPcodeFlow/1":
            raise ValueError(f"{where}: unsupported source_format")
        identity = (caller, call_address, call_time)
        if identity in seen_sites:
            raise ValueError(f"{where}: duplicate direct call site {identity}")
        seen_sites.add(identity)
        observations.append({
            "program_id": current_program,
            "caller_entry": caller,
            "callee_entry": callee,
            "call_address": call_address,
            "call_time": call_time,
            "argument_count": argument_count,
            "source_record_index": line_no,
        })
    return observations, digest, program_id, program_sha256


def check_callsite_compatibility(observations_path: Path, prototypes_path: Path) -> list[dict[str, Any]]:
    """Compare observed direct-call arity with a stored Ghidra signature."""
    prototypes, program_id, program_sha256, architecture, prototype_sha256 = _read_prototypes(prototypes_path)
    observations, observations_sha256, observations_program_id, observations_program_sha256 = _read_observations(observations_path)
    if observations_program_id is not None and observations_program_id != program_id:
        raise ValueError("program_id differs between call observations and prototype snapshots")
    if observations_program_sha256 is not None and observations_program_sha256 != program_sha256:
        raise ValueError("program_sha256 differs between call observations and prototype snapshots")

    results = []
    for observation in observations:
        prototype = prototypes.get(observation["callee_entry"])
        if prototype is None:
            status = "no_signature"
            count = has_varargs = source = prototype_ref = None
        else:
            count = prototype["parameter_count"]
            has_varargs = prototype["has_varargs"]
            source = prototype["signature_source"]
            compatible = observation["argument_count"] >= count if has_varargs else observation["argument_count"] == count
            status = "compatible" if compatible else "incompatible"
            prototype_ref = {
                "artifact_sha256": prototype_sha256,
                "record_index": prototype["record_index"],
                "source_format": PROTOTYPE_FORMAT,
            }
        results.append({
            "format": FORMAT,
            "program_id": program_id,
            "program_sha256": program_sha256,
            "architecture": architecture,
            "caller_entry": observation["caller_entry"],
            "callee_entry": observation["callee_entry"],
            "call_address": observation["call_address"],
            "call_time": observation["call_time"],
            "observed_argument_count": observation["argument_count"],
            "expected_parameter_count": count,
            "has_varargs": has_varargs,
            "signature_source": source,
            "status": status,
            "call_evidence_ref": {
                "artifact_sha256": observations_sha256,
                "record_index": observation["source_record_index"],
                "source_format": OBSERVATION_FORMAT,
            },
            "prototype_evidence_ref": prototype_ref,
        })
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("observations", type=Path, help="DirectCallArgumentObservation/1 JSONL")
    parser.add_argument("prototypes", type=Path, help="GhidraFunctionPrototype/1 JSONL")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        rows = check_callsite_compatibility(args.observations, args.prototypes)
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    print("format:", FORMAT)
    print("call sites:", len(rows))
    print("incompatible:", sum(row["status"] == "incompatible" for row in rows))
    print("without prototype:", sum(row["status"] == "no_signature" for row in rows))
    print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
