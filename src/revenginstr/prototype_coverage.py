"""Audit population, decompilation, P-code, and direct-call prototype evidence coverage."""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, TextIO

from revenginstr.prototype_inference import (
    CALL_FORMAT,
    DECOMPILER_FORMAT,
    _address,
    _read_calls,
    _read_decompiler,
    _read_jsonl,
)

FORMAT = "REVENGINSTR.FunctionPrototypeEvidenceCoverage/1"
FLOW_COLUMNS = {
    "function_entry", "op_address", "op_time", "opcode", "output", "inputs",
    "callee_entry", "callee_name",
}
INDEX_HEADER = ["entry", "name", "address_count", "is_external", "signature"]


def _canonical_address(value: str) -> str:
    return value[2:] if value.lower().startswith("0x") else value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _text_open(path: Path) -> TextIO:
    if path.suffix == ".gz":
        return gzip.open(path, "rt", encoding="utf-8", newline="")
    return path.open("r", encoding="utf-8", newline="")


def _read_function_index(path: Path) -> tuple[dict[str, dict[str, Any]], str]:
    functions: dict[str, dict[str, Any]] = {}
    with _text_open(path) as handle:
        reader = csv.DictReader(handle, delimiter="\t", strict=True)
        if reader.fieldnames != INDEX_HEADER:
            raise ValueError(f"{path}: expected exact GhidraProgramIndex/1 functions header")
        for line_no, row in enumerate(reader, 2):
            where = f"{path}:{line_no}"
            if None in row or any(value is None for value in row.values()):
                raise ValueError(f"{where}: malformed function row")
            entry = _address(row["entry"], f"{where}: entry")
            if row["is_external"] not in {"true", "false"}:
                raise ValueError(f"{where}: invalid is_external")
            if not row["address_count"].isdecimal():
                raise ValueError(f"{where}: invalid address_count")
            if entry in functions:
                raise ValueError(f"{where}: duplicate function entry {entry}")
            functions[entry] = {"is_external": row["is_external"] == "true"}
    if not functions:
        raise ValueError(f"{path}: function index is empty")
    return functions, _sha256(path)


def _read_acquisition(path: Path, program_id: str) -> tuple[dict[str, dict[str, Any]], str]:
    rows, digest = _read_jsonl(path)
    entries: dict[str, dict[str, Any]] = {}
    required = {"format", "program", "function_entry", "state", "operation_count", "callind_count", "error"}
    for line_no, row in rows:
        where = f"{path}:{line_no}"
        if set(row) != required or row.get("format") != "REVENGINSTR.GhidraPcodeFlowAcquisition/1":
            raise ValueError(f"{where}: expected GhidraPcodeFlowAcquisition/1 with exact fields")
        if row["program"] != program_id:
            raise ValueError(f"{where}: acquisition program does not match {program_id!r}")
        if row["error"] is not None and not isinstance(row["error"], str):
            raise ValueError(f"{where}: error must be string or null")
        entry = _address(row["function_entry"], f"{where}: function_entry")
        if not isinstance(row["state"], str) or row["state"] not in {"complete", "no_pcode", "decompile_failed"}:
            raise ValueError(f"{where}: invalid state")
        for field in ("operation_count", "callind_count"):
            if type(row[field]) is not int or row[field] < 0:
                raise ValueError(f"{where}: invalid {field}")
        if row["state"] == "complete" and row["operation_count"] < 1:
            raise ValueError(f"{where}: complete state requires P-code operations")
        if row["state"] != "complete" and row["operation_count"] != 0:
            raise ValueError(f"{where}: unavailable state must have zero operation_count")
        if row["state"] != "complete" and row["callind_count"] != 0:
            raise ValueError(f"{where}: unavailable state must have zero callind_count")
        if row["callind_count"] > row["operation_count"]:
            raise ValueError(f"{where}: callind_count exceeds operation_count")
        if entry in entries:
            raise ValueError(f"{where}: duplicate acquisition entry {entry}")
        entries[entry] = row
    return entries, digest


def _read_flow_files(paths: list[Path]) -> tuple[
    dict[str, int], dict[tuple[str, str, int, str], dict[str, Any]],
    dict[tuple[str, str, int], None], dict[tuple[str, str, int], None], dict[str, int],
    dict[tuple[str, int], tuple[str, str, int, str] | None], list[dict[str, Any]],
]:
    counts: dict[str, int] = {}
    calls: dict[tuple[str, str, int, str], dict[str, Any]] = {}
    unresolved_direct_calls: dict[tuple[str, str, int], None] = {}
    indirect_calls: dict[tuple[str, str, int], None] = {}
    indirect_counts: dict[str, int] = {}
    source_rows: dict[tuple[str, int], tuple[str, str, int, str] | None] = {}
    artifacts = []
    seen_paths: set[Path] = set()
    for path in sorted((path.resolve() for path in paths), key=str):
        if path in seen_paths:
            continue
        seen_paths.add(path)
        digest = _sha256(path)
        record_count = 0
        seen_operations: set[tuple[str, str, int]] = set()
        with _text_open(path) as handle:
            reader = csv.DictReader(handle, delimiter="\t", strict=True)
            if reader.fieldnames is None or len(reader.fieldnames) != len(set(reader.fieldnames)) or set(reader.fieldnames) != FLOW_COLUMNS:
                raise ValueError(f"{path}: expected exact GhidraFunctionPcodeFlow/1 columns")
            for record_count, row in enumerate(reader, 1):
                where = f"{path}:data-row-{record_count}"
                if None in row or any(value is None for value in row.values()):
                    raise ValueError(f"{where}: malformed TSV row")
                caller = _address(row["function_entry"], f"{where}: function_entry")
                address = _address(row["op_address"], f"{where}: op_address")
                if not row["op_time"].isdecimal():
                    raise ValueError(f"{where}: invalid op_time")
                time = int(row["op_time"])
                operation_key = (caller, address, time)
                if operation_key in seen_operations:
                    raise ValueError(f"{where}: duplicate P-code operation {operation_key}")
                seen_operations.add(operation_key)
                counts[caller] = counts.get(caller, 0) + 1
                if row["opcode"] == "CALLIND":
                    indirect_key = (caller, address, time)
                    if indirect_key in indirect_calls:
                        raise ValueError(f"{where}: duplicate CALLIND site {indirect_key}")
                    indirect_calls[indirect_key] = None
                    indirect_counts[caller] = indirect_counts.get(caller, 0) + 1
                if row["opcode"] == "CALL" and row["callee_entry"] == "-":
                    unresolved_key = (caller, address, time)
                    if unresolved_key in unresolved_direct_calls:
                        raise ValueError(f"{where}: duplicate unresolved CALL site {unresolved_key}")
                    unresolved_direct_calls[unresolved_key] = None
                    source_rows[(digest, record_count)] = None
                    continue
                if row["opcode"] != "CALL":
                    source_rows[(digest, record_count)] = None
                    continue
                callee = _address(row["callee_entry"], f"{where}: callee_entry")
                key = (caller, address, time, callee)
                if key in calls:
                    raise ValueError(f"{where}: duplicate direct call site {key}")
                calls[key] = {"artifact_sha256": digest, "record_index": record_count}
                source_rows[(digest, record_count)] = key
        artifacts.append({"artifact_sha256": digest, "source_format": "REVENGINSTR.GhidraFunctionPcodeFlow/1", "record_count": record_count})
    if not artifacts:
        raise ValueError("at least one P-code flow TSV is required")
    return counts, calls, unresolved_direct_calls, indirect_calls, indirect_counts, source_rows, artifacts


def _read_indirect_evidence(path: Path, program_id: str) -> tuple[dict[tuple[str, str, int], None], str]:
    rows, digest = _read_jsonl(path)
    sites: dict[tuple[str, str, int], None] = {}
    required = {
        "format", "program", "requested", "function_entry", "call_address", "call_time",
        "target", "target_expression", "arg_count",
    }
    for line_no, row in rows:
        where = f"{path}:{line_no}"
        if set(row) != required or row.get("format") != "REVENGINSTR.GhidraIndirectCallEvidence/1":
            raise ValueError(f"{where}: expected GhidraIndirectCallEvidence/1 with exact fields")
        if row["program"] != program_id:
            raise ValueError(f"{where}: indirect-call program does not match {program_id!r}")
        function = _canonical_address(_address(row["function_entry"], f"{where}: function_entry"))
        call_address = _canonical_address(_address(row["call_address"], f"{where}: call_address"))
        if type(row["call_time"]) is not int or row["call_time"] < 0:
            raise ValueError(f"{where}: invalid call_time")
        if type(row["arg_count"]) is not int or row["arg_count"] < 0:
            raise ValueError(f"{where}: invalid arg_count")
        if not isinstance(row["target"], str) or not row["target"] or not isinstance(row["target_expression"], str):
            raise ValueError(f"{where}: invalid indirect target evidence")
        key = (function, call_address, row["call_time"])
        if key in sites:
            raise ValueError(f"{where}: duplicate indirect call site {key}")
        sites[key] = None
    return sites, digest


def audit_prototype_coverage(
    function_index_path: Path,
    acquisition_path: Path,
    decompiler_path: Path,
    observations_path: Path,
    indirect_evidence_path: Path,
    flow_paths: list[Path],
) -> dict[str, Any]:
    functions, index_sha = _read_function_index(function_index_path)
    decompiler, program_id, program_sha, decompiler_sha, architecture = _read_decompiler(decompiler_path)
    acquisitions, acquisition_sha = _read_acquisition(acquisition_path, program_id)
    observations, observations_sha = _read_calls(observations_path, program_id, program_sha)
    indirect_evidence, indirect_sha = _read_indirect_evidence(indirect_evidence_path, program_id)
    flow_counts, expected_calls, unresolved_direct_calls, expected_indirect, indirect_counts, flow_source_rows, flow_artifacts = _read_flow_files(flow_paths)

    population = set(functions)
    acquired = set(acquisitions)
    decompiled = set(decompiler)
    missing_acquisition = sorted(population - acquired)
    unexpected_acquisition = sorted(acquired - population)
    missing_decompiler = sorted(population - decompiled)
    unexpected_decompiler = sorted(decompiled - population)
    flow_without_acquisition = sorted(set(flow_counts) - acquired)
    count_mismatches = sorted(
        entry for entry, record in acquisitions.items()
        if flow_counts.get(entry, 0) != record["operation_count"]
    )
    callind_count_mismatches = sorted(
        entry for entry, record in acquisitions.items()
        if indirect_counts.get(entry, 0) != record["callind_count"]
    )
    state_counts = {state: sum(row["state"] == state for row in acquisitions.values())
                    for state in ("complete", "no_pcode", "decompile_failed")}
    decompiler_status_counts = {
        status: sum(row["status"] == status for row in decompiler.values())
        for status in ("complete", "external", "decompile_failed", "no_high_function", "prototype_unavailable")
    }

    observed_calls: dict[tuple[str, str, int, str], dict[str, Any]] = {}
    for observation in observations:
        key = (observation["caller_entry"], observation["call_address"], observation["call_time"], observation["callee_entry"])
        ref = observation["evidence_ref"]
        source_key = (ref["artifact_sha256"], ref["record_index"])
        if flow_source_rows.get(source_key) != key:
            raise ValueError("call observation source does not match its exact P-code flow row")
        if key in observed_calls:
            raise ValueError(f"duplicate observed direct call site {key}")
        observed_calls[key] = observation
    expected_keys = set(expected_calls)
    observed_keys = set(observed_calls)
    missing_calls = sorted(expected_keys - observed_keys)
    extra_calls = sorted(observed_keys - expected_keys)
    direct_call_coverage_complete = not missing_calls and not extra_calls

    internal_entries = {entry for entry, row in functions.items() if not row["is_external"]}
    external_entries = population - internal_entries
    pcode_complete = (
        not missing_acquisition and not unexpected_acquisition and not flow_without_acquisition and
        not count_mismatches and not callind_count_mismatches and
        all(acquisitions.get(entry, {}).get("state") == "complete" for entry in internal_entries) and
        all(acquisitions.get(entry, {}).get("state") == "no_pcode" for entry in external_entries)
    )
    decompiler_complete = (
        not missing_decompiler and not unexpected_decompiler and
        all(decompiler.get(entry, {}).get("status") == "complete" for entry in internal_entries) and
        all(decompiler.get(entry, {}).get("status") == "external" for entry in external_entries)
    )
    missing_indirect = sorted(set(expected_indirect) - set(indirect_evidence))
    extra_indirect = sorted(set(indirect_evidence) - set(expected_indirect))
    indirect_call_coverage_complete = not missing_indirect and not extra_indirect
    full_coverage = pcode_complete and decompiler_complete and direct_call_coverage_complete and indirect_call_coverage_complete
    source_artifacts = {
        "function_index": {"artifact_sha256": index_sha, "source_format": "REVENGINSTR.GhidraProgramIndex.Functions/1"},
        "acquisition": {"artifact_sha256": acquisition_sha, "source_format": "REVENGINSTR.GhidraPcodeFlowAcquisition/1"},
        "decompiler_parameters": {"artifact_sha256": decompiler_sha, "source_format": DECOMPILER_FORMAT},
        "call_observations": {"artifact_sha256": observations_sha, "source_format": CALL_FORMAT},
        "indirect_call_evidence": {"artifact_sha256": indirect_sha, "source_format": "REVENGINSTR.GhidraIndirectCallEvidence/1"},
        "flows": flow_artifacts,
    }
    return {
        "format": FORMAT,
        "program_id": program_id,
        "program_sha256": program_sha,
        "architecture": architecture,
        "source_artifacts": source_artifacts,
        "function_population": {"total": len(population), "internal": len(internal_entries), "external": len(external_entries)},
        "pcode_flow": {
            "requested": len(acquired), "state_counts": state_counts,
            "flow_rows": sum(flow_counts.values()), "missing_entries": missing_acquisition,
            "unexpected_entries": unexpected_acquisition, "rows_without_acquisition": flow_without_acquisition,
            "operation_count_mismatches": count_mismatches, "callind_count_mismatches": callind_count_mismatches,
            "complete_for_population": pcode_complete,
        },
        "decompiler_parameters": {
            "selected": len(decompiled), "status_counts": decompiler_status_counts,
            "missing_entries": missing_decompiler, "unexpected_entries": unexpected_decompiler,
            "complete_for_population": decompiler_complete,
        },
        "direct_calls": {
            "expected_resolved_sites": len(expected_calls), "observed_sites": len(observations),
            "unresolved_sites": [dict(function_entry=key[0], call_address=key[1], call_time=key[2]) for key in sorted(unresolved_direct_calls)],
            "missing_sites": [dict(caller_entry=key[0], call_address=key[1], call_time=key[2], callee_entry=key[3]) for key in missing_calls],
            "extra_sites": [dict(caller_entry=key[0], call_address=key[1], call_time=key[2], callee_entry=key[3]) for key in extra_calls],
            "complete_for_flow_artifacts": direct_call_coverage_complete,
        },
        "indirect_calls": {
            "expected_sites": len(expected_indirect), "observed_sites": len(indirect_evidence),
            "missing_sites": [dict(function_entry=key[0], call_address=key[1], call_time=key[2]) for key in missing_indirect],
            "extra_sites": [dict(function_entry=key[0], call_address=key[1], call_time=key[2]) for key in extra_indirect],
            "complete_for_flow_artifacts": indirect_call_coverage_complete,
        },
        "full_program_coverage": full_coverage,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("function_index", type=Path, help="GhidraProgramIndex functions TSV or TSV.GZ")
    parser.add_argument("acquisition", type=Path, help="GhidraPcodeFlowAcquisition/1 JSONL")
    parser.add_argument("decompiler_parameters", type=Path, help="GhidraDecompilerParameters/1 JSONL")
    parser.add_argument("call_observations", type=Path, help="DirectCallArgumentObservation/1 JSONL")
    parser.add_argument("indirect_call_evidence", type=Path, help="GhidraIndirectCallEvidence/1 JSONL")
    parser.add_argument("flows", nargs="+", type=Path, help="GhidraFunctionPcodeFlow/1 TSV files")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    inputs = {path.resolve() for path in [args.function_index, args.acquisition, args.decompiler_parameters, args.call_observations, args.indirect_call_evidence, *args.flows]}
    if args.output.resolve() in inputs:
        print("error: output path must differ from all inputs", file=sys.stderr)
        return 2
    try:
        report = audit_prototype_coverage(
            args.function_index, args.acquisition, args.decompiler_parameters,
            args.call_observations, args.indirect_call_evidence, args.flows,
        )
    except (OSError, ValueError, EOFError, csv.Error, gzip.BadGzipFile) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_name(args.output.name + ".tmp")
    try:
        temporary.write_text(json.dumps(report, sort_keys=True, indent=2, allow_nan=False) + "\n", encoding="utf-8")
        temporary.replace(args.output)
    finally:
        temporary.unlink(missing_ok=True)
    print("format:", FORMAT)
    print("functions:", report["function_population"]["total"])
    print("full program coverage:", report["full_program_coverage"])
    print("missing direct calls:", len(report["direct_calls"]["missing_sites"]))
    print("unresolved direct calls:", len(report["direct_calls"]["unresolved_sites"]))
    print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
