"""Reconcile canonical function populations with High-P-code CALLIND sites."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Iterator

POPULATION_FORMAT = "REVENGINSTR.CallindPopulation/1"
INVENTORY_FORMAT = "REVENGINSTR.CallindInventory/1"
SUMMARY_FORMAT = "REVENGINSTR.CallindInventorySummary/1"
FLOW_FORMAT = "REVENGINSTR.GhidraFunctionPcodeFlow/1"
CALL_EVIDENCE_FORMAT = "REVENGINSTR.GhidraIndirectCallEvidence/1"
POPULATION_STATES = {
    "complete", "truncated", "no_pcode", "decompile_failed", "export_failed",
    "not_exported", "unknown",
}
FLOW_FIELDS = {
    "function_entry", "op_address", "op_time", "opcode", "output", "inputs",
    "callee_entry", "callee_name",
}
ADDRESS_RE = re.compile(r"^(?:(?P<space>[A-Za-z_$][\w$]*):)?(?:0x)?(?P<offset>[0-9a-fA-F]+)$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _address_key(value: Any, where: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{where}: expected address string")
    match = ADDRESS_RE.fullmatch(value.strip())
    if match is None:
        raise ValueError(f"{where}: unsupported address {value!r}")
    offset = int(match.group("offset"), 16)
    space = match.group("space")
    return f"{space.lower() + ':' if space else ''}0x{offset:x}"


def _read_jsonl(path: Path) -> Iterator[tuple[int, dict[str, Any]]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        for line_no, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            try:
                row = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
            except ValueError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_no}: expected a JSON object")
            yield line_no, row


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-JSON numeric constant {value}")


def _source(path: Path, sha256: str, record_index: int) -> dict[str, Any]:
    return {
        "artifact_path": str(path),
        "artifact_sha256": sha256,
        "record_index": record_index,
    }


def _validate_canonical_source(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"{where}: expected source object")
    if set(value) != {"source_format", "artifact_sha256", "record_index"}:
        raise ValueError(f"{where}: canonical_source has missing or unknown fields")
    source_format = value.get("source_format")
    artifact_sha256 = value.get("artifact_sha256")
    record_index = value.get("record_index")
    if not isinstance(source_format, str) or not source_format:
        raise ValueError(f"{where}: source_format must be non-empty")
    if not isinstance(artifact_sha256, str) or SHA256_RE.fullmatch(artifact_sha256) is None:
        raise ValueError(f"{where}: artifact_sha256 must be lowercase SHA-256")
    if isinstance(record_index, bool) or not isinstance(record_index, int) or record_index < 1:
        raise ValueError(f"{where}: record_index must be a positive integer")
    return {
        "source_format": source_format,
        "artifact_sha256": artifact_sha256,
        "record_index": record_index,
    }


def read_population(path: Path) -> tuple[list[dict[str, Any]], str]:
    """Read the normalized, hash-linked expected function population."""
    artifact_sha256 = _sha256(path)
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    program_ids: set[str] = set()
    for line_no, row in _read_jsonl(path):
        where = f"{path}:{line_no}"
        allowed = {
            "format", "program_id", "function_entry", "acquisition_state",
            "expected_callind_count", "canonical_truncated", "canonical_source",
        }
        if set(row) - allowed or "expected_callind_count" not in row:
            raise ValueError(f"{where}: population row has missing or unknown fields")
        if row.get("format") != POPULATION_FORMAT:
            raise ValueError(f"{where}: expected {POPULATION_FORMAT}")
        program_id = row.get("program_id")
        entry = row.get("function_entry")
        state = row.get("acquisition_state")
        expected = row.get("expected_callind_count")
        canonical_source = _validate_canonical_source(row.get("canonical_source"), where)
        canonical_truncated = row.get("canonical_truncated", False)
        if not isinstance(program_id, str) or not program_id:
            raise ValueError(f"{where}: program_id must be non-empty")
        if not isinstance(state, str) or state not in POPULATION_STATES:
            raise ValueError(f"{where}: unsupported acquisition_state {state!r}")
        if expected is not None and (
            isinstance(expected, bool) or not isinstance(expected, int) or expected < 0
        ):
            raise ValueError(f"{where}: expected_callind_count must be null or a non-negative integer")
        if not isinstance(canonical_truncated, bool):
            raise ValueError(f"{where}: canonical_truncated must be boolean")
        entry_key = _address_key(entry, f"{where}: function_entry")
        identity = (program_id, entry_key)
        if identity in seen:
            raise ValueError(f"{where}: duplicate population function {program_id}:{entry}")
        seen.add(identity)
        program_ids.add(program_id)
        rows.append({
            "program_id": program_id,
            "function_entry": entry,
            "function_key": entry_key,
            "acquisition_state": state,
            "expected_callind_count": expected,
            "canonical_truncated": canonical_truncated,
            "canonical_source": canonical_source,
            "population_source": _source(path, artifact_sha256, line_no),
        })
    if not rows:
        raise ValueError(f"{path}: function population is empty")
    if len(program_ids) != 1:
        raise ValueError(f"{path}: one population file must contain exactly one program_id")
    return rows, artifact_sha256


def _input_paths(files: Iterable[Path], directories: Iterable[Path], suffix: str) -> list[Path]:
    paths = set(files)
    for directory in directories:
        if not directory.is_dir():
            raise ValueError(f"not a directory: {directory}")
        paths.update(path for path in directory.rglob(f"*{suffix}") if path.is_file())
    result = sorted(paths, key=lambda path: str(path))
    for path in result:
        if not path.is_file():
            raise ValueError(f"not a file: {path}")
    return result


def read_flows(paths: Iterable[Path]) -> tuple[dict[str, list[dict[str, Any]]], dict[str, dict[str, Any]]]:
    flows: dict[str, list[dict[str, Any]]] = defaultdict(list)
    source_counts: dict[str, dict[str, Any]] = {}
    operation_keys: set[tuple[str, str, str]] = set()
    for path in paths:
        digest = _sha256(path)
        count = 0
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle, delimiter="\t")
            if reader.fieldnames is None or len(reader.fieldnames) != len(set(reader.fieldnames)) or set(reader.fieldnames) != FLOW_FIELDS:
                raise ValueError(f"{path}: expected the exact GhidraFunctionPcodeFlow/1 columns")
            for record_index, row in enumerate(reader, 1):
                where = f"{path}:data-row-{record_index}"
                function_key = _address_key(row.get("function_entry"), f"{where}: function_entry")
                address_key = _address_key(row.get("op_address"), f"{where}: op_address")
                time_text = row.get("op_time")
                if not isinstance(time_text, str) or not time_text.isdecimal():
                    raise ValueError(f"{where}: op_time must be a non-negative decimal integer")
                opcode = row.get("opcode")
                if not isinstance(opcode, str) or not opcode:
                    raise ValueError(f"{where}: opcode must be non-empty")
                operation_key = (function_key, address_key, str(int(time_text)))
                if operation_key in operation_keys:
                    raise ValueError(f"{where}: duplicate operation identity {operation_key}")
                operation_keys.add(operation_key)
                source_ref = _source(path, digest, record_index)
                inputs = row.get("inputs", "")
                if not isinstance(inputs, str):
                    raise ValueError(f"{where}: inputs must be a string")
                operation = {
                    "function_key": function_key,
                    "op_address": row["op_address"],
                    "call_address_key": address_key,
                    "op_time": int(time_text),
                    "opcode": opcode,
                    "inputs": inputs,
                    "source": source_ref,
                }
                flows[function_key].append(operation)
                count += 1
        source_counts[str(path)] = {
            "artifact_path": str(path),
            "artifact_sha256": digest,
            "record_count": count,
        }
    return flows, source_counts


def read_call_evidence(paths: Iterable[Path]) -> tuple[dict[tuple[str, str, str, int], dict[str, Any]], dict[str, dict[str, Any]]]:
    evidence: dict[tuple[str, str, str, int], dict[str, Any]] = {}
    source_counts: dict[str, dict[str, Any]] = {}
    for path in paths:
        digest = _sha256(path)
        count = 0
        for record_index, row in _read_jsonl(path):
            where = f"{path}:{record_index}"
            required = {
                "format", "program", "requested", "function_entry", "call_address",
                "call_time", "target", "target_expression", "arg_count",
            }
            if set(row) != required:
                raise ValueError(f"{where}: indirect-call evidence has missing or unknown fields")
            if row.get("format") != CALL_EVIDENCE_FORMAT:
                raise ValueError(f"{where}: expected {CALL_EVIDENCE_FORMAT}")
            program_id = row.get("program")
            if not isinstance(program_id, str) or not program_id:
                raise ValueError(f"{where}: program must be non-empty")
            requested = row.get("requested")
            if not isinstance(requested, str) or not requested:
                raise ValueError(f"{where}: requested must be non-empty")
            call_time = row.get("call_time")
            arg_count = row.get("arg_count")
            if isinstance(call_time, bool) or not isinstance(call_time, int) or call_time < 0:
                raise ValueError(f"{where}: call_time must be a non-negative integer")
            if isinstance(arg_count, bool) or not isinstance(arg_count, int) or arg_count < 0:
                raise ValueError(f"{where}: arg_count must be a non-negative integer")
            target = row.get("target")
            expression = row.get("target_expression")
            if not isinstance(target, str) or not target:
                raise ValueError(f"{where}: target must be non-empty")
            if not isinstance(expression, str) or not expression:
                raise ValueError(f"{where}: target_expression must be non-empty")
            function_key = _address_key(row.get("function_entry"), f"{where}: function_entry")
            address_key = _address_key(row.get("call_address"), f"{where}: call_address")
            key = (program_id, function_key, address_key, call_time)
            if key in evidence:
                raise ValueError(f"{where}: duplicate CALLIND evidence site {key}")
            evidence[key] = {
                "target": target,
                "target_expression": expression,
                "arg_count": arg_count,
                "source": _source(path, digest, record_index),
            }
            count += 1
        source_counts[str(path)] = {
            "artifact_path": str(path),
            "artifact_sha256": digest,
            "record_count": count,
        }
    return evidence, source_counts


def _expression_markers(expression: str | None) -> list[str]:
    if expression is None:
        return []
    return [marker for marker in ("cycle", "depth-limit") if f"{{{marker}}}" in expression]


def _count_reconciliation(state: str, expected: int | None, observed: int | None) -> str:
    if state == "export_missing":
        return "export_missing"
    if state in {"decompile_failed", "export_failed", "no_pcode"}:
        return "failed"
    if state == "not_exported":
        return "not_exported"
    if observed is None or expected is None:
        return "not_comparable" if state != "unknown" else "unknown"
    if state == "complete":
        return "matched" if observed == expected else "mismatch"
    if state == "truncated":
        if observed > expected:
            return "mismatch"
        return "matched" if observed == expected else "lower_bound"
    return "unknown"


def build_inventory(
    population: list[dict[str, Any]],
    flows: dict[str, list[dict[str, Any]]],
    evidence: dict[tuple[str, str, str, int], dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Create one function record per population member and one row per CALLIND."""
    by_identity = {(row["program_id"], row["function_key"]): row for row in population}
    # Flow TSV does not carry a program id, so it is scoped to the single program in the population.
    program_id = population[0]["program_id"]
    flow_entries = set(flows)
    extra_entries = flow_entries - {entry for (_, entry) in by_identity}
    if extra_entries:
        raise ValueError(f"P-code flow contains functions outside the canonical population: {sorted(extra_entries)}")

    site_keys: set[tuple[str, str, str, int]] = set()
    records: list[dict[str, Any]] = []
    states: Counter[str] = Counter()
    reconciliation: Counter[str] = Counter()
    site_count = evidence_count = expression_missing = 0
    expected_total = 0
    expected_known = 0
    observed_total = 0
    observed_known = 0

    for function in sorted(population, key=lambda row: row["function_key"]):
        key = (program_id, function["function_key"])
        operations = flows.get(function["function_key"], [])
        state = function["acquisition_state"]
        has_flow = key[1] in flow_entries
        if state in {"decompile_failed", "no_pcode", "export_failed", "not_exported"} and has_flow:
            raise ValueError(f"{program_id}:{function['function_entry']}: flow exists for {state} function")
        if state in {"complete", "truncated"} and not has_flow:
            state = "export_missing"
        if state == "unknown" and not has_flow:
            state = "unknown"

        call_sites = [row for row in operations if row["opcode"] == "CALLIND"]
        observed = len(call_sites) if has_flow else None
        count_status = _count_reconciliation(state, function["expected_callind_count"], observed)
        states[state] += 1
        reconciliation[count_status] += 1
        if function["expected_callind_count"] is not None:
            expected_known += 1
            expected_total += function["expected_callind_count"]
        if observed is not None:
            observed_known += 1
            observed_total += observed

        flow_sources: dict[str, dict[str, Any]] = {}
        for operation in operations:
            source = operation["source"]
            entry = flow_sources.setdefault(source["artifact_sha256"], {
                "artifact_path": source["artifact_path"],
                "artifact_sha256": source["artifact_sha256"],
                "record_count": 0,
            })
            entry["record_count"] += 1
        records.append({
            "format": INVENTORY_FORMAT,
            "record_kind": "function",
            "program_id": program_id,
            "function_entry": function["function_entry"],
            "acquisition_state": state,
            "declared_acquisition_state": function["acquisition_state"],
            "observed_callind_count": observed,
            "expected_callind_count": function["expected_callind_count"],
            "count_reconciliation": count_status,
            "canonical_truncated": function["canonical_truncated"],
            "population_source": function["population_source"],
            "canonical_source": function["canonical_source"],
            "flow_sources": sorted(flow_sources.values(), key=lambda row: row["artifact_path"]),
        })

        for operation in sorted(call_sites, key=lambda row: (row["call_address_key"], row["op_time"])):
            site_key = (program_id, function["function_key"], operation["call_address_key"], operation["op_time"])
            site_keys.add(site_key)
            site_evidence = evidence.get(site_key)
            expression = site_evidence["target_expression"] if site_evidence else None
            markers = _expression_markers(expression)
            inputs = operation["inputs"]
            observed_arg_count = 0 if inputs in {"", "-"} else len(inputs.split(";"))
            if site_evidence is not None:
                if site_evidence["arg_count"] != observed_arg_count:
                    raise ValueError(
                        f"{program_id}:{function['function_entry']}:{operation['op_address']}:{operation['op_time']}: "
                        f"CALLIND evidence arg_count {site_evidence['arg_count']} does not match P-code flow "
                        f"input count {observed_arg_count}"
                    )
                evidence_count += 1
            else:
                expression_missing += 1
            records.append({
                "format": INVENTORY_FORMAT,
                "record_kind": "callind_site",
                "program_id": program_id,
                "function_entry": function["function_entry"],
                "call_address": operation["op_address"],
                "call_time": operation["op_time"],
                "acquisition_state": state,
                "target": site_evidence["target"] if site_evidence else None,
                "target_expression": expression,
                "expression_status": "present" if expression is not None else "missing",
                "expression_markers": markers,
                "classification": "unknown",
                "classification_basis": [],
                "pcode_source": operation["source"],
                "indirect_call_evidence_source": site_evidence["source"] if site_evidence else None,
            })
            site_count += 1

    extra_evidence = set(evidence) - site_keys
    if extra_evidence:
        raise ValueError(f"indirect-call evidence has no exact CALLIND flow match: {sorted(extra_evidence)[:5]}")

    summary = {
        "format": SUMMARY_FORMAT,
        "program_id": program_id,
        "population_functions": len(population),
        "functions_with_flow": observed_known,
        "canonical_truncated_functions": sum(row["canonical_truncated"] for row in population),
        "callind_sites": site_count,
        "sites_with_expression_evidence": evidence_count,
        "sites_missing_expression_evidence": expression_missing,
        "expected_callind_count_known_functions": expected_known,
        "expected_callind_count_total": expected_total,
        "observed_callind_count_functions": observed_known,
        "observed_callind_count_total": observed_total,
        "site_classification_counts": dict(sorted(Counter(
            row["classification"] for row in records if row["record_kind"] == "callind_site"
        ).items())),
        "sites_with_cycle_marker": sum(
            "cycle" in row["expression_markers"] for row in records if row["record_kind"] == "callind_site"
        ),
        "sites_with_depth_limit_marker": sum(
            "depth-limit" in row["expression_markers"] for row in records if row["record_kind"] == "callind_site"
        ),
        "acquisition_state_counts": dict(sorted(states.items())),
        "count_reconciliation_counts": dict(sorted(reconciliation.items())),
    }
    return records, summary


def _write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
            handle.write("\n")


def inventory(
    population_path: Path,
    flow_paths: Iterable[Path],
    evidence_paths: Iterable[Path],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    population, population_sha256 = read_population(population_path)
    flows, flow_sources = read_flows(flow_paths)
    evidence, evidence_sources = read_call_evidence(evidence_paths)
    records, summary = build_inventory(population, flows, evidence)
    summary["population_manifest_sha256"] = population_sha256
    summary["flow_artifacts"] = sorted(flow_sources.values(), key=lambda row: row["artifact_path"])
    summary["indirect_call_evidence_artifacts"] = sorted(
        evidence_sources.values(), key=lambda row: row["artifact_path"]
    )
    return records, summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("population", type=Path, help=f"JSONL {POPULATION_FORMAT} function population")
    parser.add_argument("output", type=Path, help=f"JSONL {INVENTORY_FORMAT} output")
    parser.add_argument("--pcode-flow", action="append", type=Path, default=[], help="High-P-code flow TSV; repeatable")
    parser.add_argument("--pcode-flow-dir", action="append", type=Path, default=[], help="recursively read *.tsv files")
    parser.add_argument("--indirect-call-evidence", action="append", type=Path, default=[], help="CALLIND evidence JSONL; repeatable")
    parser.add_argument("--indirect-call-evidence-dir", action="append", type=Path, default=[], help="recursively read *.jsonl files")
    parser.add_argument("--summary", type=Path, help="write a machine-readable summary JSON")
    args = parser.parse_args(argv)

    try:
        flows = _input_paths(args.pcode_flow, args.pcode_flow_dir, ".tsv")
        evidence = _input_paths(args.indirect_call_evidence, args.indirect_call_evidence_dir, ".jsonl")
        records, summary = inventory(args.population, flows, evidence)
        _write_jsonl(args.output, records)
        rendered = json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        if args.summary:
            args.summary.parent.mkdir(parents=True, exist_ok=True)
            args.summary.write_text(rendered, encoding="utf-8")
        sys.stdout.write(rendered)
    except (OSError, UnicodeError, csv.Error, ValueError) as exc:
        print(f"CALLIND inventory: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
