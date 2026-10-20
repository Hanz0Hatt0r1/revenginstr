"""Summarize direct-call effects and optionally join scoped static CALLIND targets."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from revenginstr.pcode.opcodes import NO_EXPLICIT_MEMORY_WRITE_OPCODES
from .call_effects import (
    MAX_CALLS,
    MAX_FLOW_BYTES,
    MAX_FLOW_OPERATIONS,
    _read_callee_flows,
    _read_pcode_flow,
)

FORMAT_V1 = "REVENGINSTR.GhidraDirectCallMemoryEffectClosure/1"
FORMAT_V2 = "REVENGINSTR.GhidraDirectCallMemoryEffectClosure/2"
FORMAT = FORMAT_V1
STATIC_TARGET_FORMAT = "REVENGINSTR.GhidraStaticIndirectCallTarget/1"
TARGET_TRIAGE_FORMAT = "REVENGINSTR.IndirectCallTargetTriage/1"
STATIC_TARGET_SCOPE = "observed_global_singleton_initializer"
TARGET_TRIAGE_SCOPE = "observed_constant_address_anchor_paths"
_ADDRESS = re.compile(r"(?:0x)?([0-9a-fA-F]{8})\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_CONST_ANCHOR = re.compile(r"^const:(0x[0-9a-fA-F]+):([0-9]+)$")
MAX_FUNCTIONS = 10_000
MAX_CLOSURE_VISITS = 1_000_000
MAX_TARGET_EVIDENCE_BYTES = 16 * 1024 * 1024


def _closure_summary(
    entry: str,
    flows: dict[str, tuple[str, list[dict[str, str]]]],
) -> tuple[set[str], set[str], int]:
    pending = [entry]
    reachable: set[str] = set()
    effects: set[str] = set()
    call_site_count = 0
    while pending:
        current = pending.pop()
        if current in reachable:
            continue
        flow = flows.get(current)
        if flow is None:
            effects.add("CALL")
            continue
        reachable.add(current)
        for row in flow[1]:
            opcode = row["opcode"]
            if opcode in {"CALL", "CALLIND"}:
                call_site_count += 1
                if opcode == "CALLIND":
                    effects.add("CALLIND")
                    continue
                target = row.get("callee_entry", "-")
                if not target or target == "-":
                    effects.add("CALL")
                elif target in flows:
                    pending.append(target)
                else:
                    effects.add("CALL")
            elif opcode == "STORE":
                effects.add("STORE")
            elif opcode not in NO_EXPLICIT_MEMORY_WRITE_OPCODES:
                effects.add(opcode)
    return reachable, effects, call_site_count


def _closure_digest(
    entries: set[str], flows: dict[str, tuple[str, list[dict[str, str]]]],
) -> str:
    manifest = [
        {
            "function_entry": entry,
            "pcode_flow_sha256": flows[entry][0],
            "pcode_flow_record_count": len(flows[entry][1]),
        }
        for entry in sorted(entries)
    ]
    payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _address_value(value: Any, *, where: str) -> int:
    if not isinstance(value, str):
        raise ValueError(f"{where}: expected an eight-digit address")
    match = _ADDRESS.fullmatch(value)
    if match is None:
        raise ValueError(f"{where}: expected an eight-digit address")
    return int(match.group(1), 16)


def _read_jsonl_records(path: Path) -> tuple[str, list[dict[str, Any]]]:
    if path.stat().st_size > MAX_TARGET_EVIDENCE_BYTES:
        raise ValueError(f"{path}: target evidence byte budget exceeded: {MAX_TARGET_EVIDENCE_BYTES}")
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"{path}: input must be UTF-8") from error
    lines = text.splitlines()
    if not lines:
        raise ValueError(f"{path}: target evidence is empty")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON object key {key!r}")
            result[key] = value
        return result

    rows = []
    for record_index, line in enumerate(lines, 1):
        if not line.strip():
            raise ValueError(f"{path}: blank JSONL record at line {record_index}")
        try:
            row = json.loads(line, object_pairs_hook=unique_object)
        except json.JSONDecodeError as error:
            raise ValueError(f"{path}: invalid JSON at line {record_index}: {error.msg}") from error
        except ValueError as error:
            raise ValueError(f"{path}: invalid JSON at line {record_index}: {error}") from error
        if not isinstance(row, dict):
            raise ValueError(f"{path}: JSONL record {record_index} must be an object")
        rows.append(row)
    return hashlib.sha256(raw).hexdigest(), rows


def _validate_target_program(
    row: dict[str, Any], *, where: str, program_id: str, program_sha256: str,
) -> None:
    if row.get("program_id") != program_id:
        raise ValueError(f"{where}: program_id does not match --program-id")
    if row.get("program_sha256") != program_sha256:
        raise ValueError(f"{where}: program_sha256 does not match --program-sha256")
    if not isinstance(row.get("binary_program"), str) or not row["binary_program"]:
        raise ValueError(f"{where}: binary_program must be non-empty")


def _target_observation_key(row: dict[str, Any]) -> tuple[Any, ...]:
    source = row["source"]
    return (
        row["target_address"], row["resolution_scope"], source["source_format"],
        source["record_index"], source.get("target_candidate_index", 0),
    )


def _read_static_targets(
    path: Path, *, program_id: str, program_sha256: str,
) -> tuple[str, dict[tuple[int, int, int], list[dict[str, Any]]]]:
    artifact_sha256, rows = _read_jsonl_records(path)
    by_site: dict[tuple[int, int, int], list[dict[str, Any]]] = {}
    seen: set[tuple[int, int, int, int]] = set()
    required = {
        "format", "program_id", "program_sha256", "binary_program",
        "function_entry", "call_address", "call_time", "resolution_scope",
        "receiver", "slot", "target_address", "callind_evidence",
        "pointer_slot_projection", "initialization_evidence", "observed_callers",
        "limitations",
    }
    for record_index, row in enumerate(rows, 1):
        where = f"{path}: record {record_index}"
        if set(row) != required or row["format"] != STATIC_TARGET_FORMAT:
            raise ValueError(f"{where}: malformed GhidraStaticIndirectCallTarget/1 fields")
        _validate_target_program(row, where=where, program_id=program_id, program_sha256=program_sha256)
        if row["resolution_scope"] != STATIC_TARGET_SCOPE:
            raise ValueError(f"{where}: unsupported resolution_scope")
        entry = _address_value(row["function_entry"], where=f"{where}.function_entry")
        address = _address_value(row["call_address"], where=f"{where}.call_address")
        target = _address_value(row["target_address"], where=f"{where}.target_address")
        call_time = row["call_time"]
        if type(call_time) is not int or call_time < 0:
            raise ValueError(f"{where}: call_time must be a non-negative integer")
        identity = (entry, address, call_time, target)
        if identity in seen:
            raise ValueError(f"{where}: duplicate static target for one CALLIND site")
        seen.add(identity)
        by_site.setdefault((entry, address, call_time), []).append({
            "target_address": f"0x{target:08x}",
            "resolution_scope": STATIC_TARGET_SCOPE,
            "evidence_state": "observed_global_singleton_target",
            "program_sha256": program_sha256,
            "source": {
                "artifact_path": path.as_posix(),
                "artifact_sha256": artifact_sha256,
                "record_index": record_index,
                "source_format": STATIC_TARGET_FORMAT,
            },
        })
    for observations in by_site.values():
        observations.sort(key=_target_observation_key)
    return artifact_sha256, by_site


def _read_vtable_candidates(
    path: Path, *, program_id: str, program_sha256: str,
) -> tuple[str, dict[tuple[int, int, int], list[dict[str, Any]]]]:
    artifact_sha256, rows = _read_jsonl_records(path)
    by_site: dict[tuple[int, int, int], list[dict[str, Any]]] = {}
    seen: set[tuple[int, int, int, int]] = set()
    required = {
        "format", "program_id", "program_sha256", "binary_program",
        "function_entry", "call_address", "call_time", "slot_offset_bytes",
        "status", "receiver", "candidate_targets", "callind_evidence",
        "pointer_slot_projection", "limitations",
    }
    scope_by_status = {
        "bounded_static_target_candidates": "observed_cached_field_constructor_variants",
        "partial_static_target_candidates": "observed_returned_subobject_constructor_variants",
        "unresolved_return_object_vtable": None,
    }
    for record_index, row in enumerate(rows, 1):
        where = f"{path}: record {record_index}"
        if set(row) != required or row["format"] != "REVENGINSTR.GhidraIndirectCallVtableCandidates/1":
            raise ValueError(f"{where}: malformed GhidraIndirectCallVtableCandidates/1 fields")
        _validate_target_program(row, where=where, program_id=program_id, program_sha256=program_sha256)
        status = row["status"]
        if not isinstance(status, str) or status not in scope_by_status:
            raise ValueError(f"{where}: unsupported candidate status")
        candidates = row["candidate_targets"]
        if not isinstance(candidates, list):
            raise ValueError(f"{where}: candidate_targets must be an array")
        if (status == "unresolved_return_object_vtable") != (not candidates):
            raise ValueError(f"{where}: candidate status disagrees with candidate_targets")
        entry = _address_value(row["function_entry"], where=f"{where}.function_entry")
        address = _address_value(row["call_address"], where=f"{where}.call_address")
        call_time = row["call_time"]
        if type(call_time) is not int or call_time < 0:
            raise ValueError(f"{where}: call_time must be a non-negative integer")
        site = (entry, address, call_time)
        for candidate_index, candidate in enumerate(candidates, 1):
            if (
                not isinstance(candidate, dict)
                or set(candidate) != {"target_address", "vtable_origins"}
                or not isinstance(candidate["vtable_origins"], list)
                or not candidate["vtable_origins"]
            ):
                raise ValueError(f"{where}: malformed vtable candidate {candidate_index}")
            target = _address_value(candidate["target_address"], where=f"{where}.candidate[{candidate_index}]")
            identity = (*site, target)
            if identity in seen:
                raise ValueError(f"{where}: duplicate vtable target for one CALLIND site")
            seen.add(identity)
            by_site.setdefault(site, []).append({
                "target_address": f"0x{target:08x}",
                "resolution_scope": scope_by_status[status],
                "evidence_state": status,
                "program_sha256": program_sha256,
                "source": {
                    "artifact_path": path.as_posix(),
                    "artifact_sha256": artifact_sha256,
                    "record_index": record_index,
                    "target_candidate_index": candidate_index,
                    "source_format": "REVENGINSTR.GhidraIndirectCallVtableCandidates/1",
                },
            })
    for observations in by_site.values():
        observations.sort(key=_target_observation_key)
    return artifact_sha256, by_site


def _read_target_triage(
    path: Path, *, program_id: str, program_sha256: str,
) -> tuple[str, dict[tuple[int, int, int], list[dict[str, Any]]]]:
    artifact_sha256, rows = _read_jsonl_records(path)
    by_site: dict[tuple[int, int, int], list[dict[str, Any]]] = {}
    seen: set[tuple[int, int, int, int]] = set()
    required = {
        "format", "program_id", "program_sha256", "function_entry", "call_address", "call_time",
        "provenance_status", "classification", "bounded_path_count", "dynamic_barrier_count",
        "limited_path_count", "alternatives", "static_target_candidate_scope", "static_target_candidates",
        "pcode_operation", "callind_evidence", "source",
    }
    evidence_state_by_scope = {
        "bounded_static_target_candidates": "bounded_static_target_candidates",
        "partial_static_target_candidates": "partial_static_target_candidates",
    }
    for record_index, row in enumerate(rows, 1):
        where = f"{path}: record {record_index}"
        if set(row) != required or row["format"] != TARGET_TRIAGE_FORMAT:
            raise ValueError(f"{where}: malformed {TARGET_TRIAGE_FORMAT} fields")
        if row["program_id"] != program_id or row["program_sha256"] != program_sha256:
            raise ValueError(f"{where}: analyzed-program identity does not match the closure inputs")
        entry = _address_value(row["function_entry"], where=f"{where}.function_entry")
        address = _address_value(row["call_address"], where=f"{where}.call_address")
        call_time = row["call_time"]
        if type(call_time) is not int or call_time < 0:
            raise ValueError(f"{where}: call_time must be a non-negative integer")
        candidate_scope = row["static_target_candidate_scope"]
        candidates = row["static_target_candidates"]
        if not isinstance(candidates, list):
            raise ValueError(f"{where}: static_target_candidates must be an array")
        if candidate_scope == "none":
            if candidates:
                raise ValueError(f"{where}: candidate scope disagrees with empty candidates")
            continue
        evidence_state = evidence_state_by_scope.get(candidate_scope)
        if evidence_state is None or not candidates:
            raise ValueError(f"{where}: unsupported static target candidate scope")
        alternatives = row["alternatives"]
        if not isinstance(alternatives, list) or not alternatives:
            raise ValueError(f"{where}: alternatives must be a non-empty array")
        site = (entry, address, call_time)
        for candidate_index, candidate in enumerate(candidates, 1):
            if not isinstance(candidate, dict) or set(candidate) != {"target_address", "alternative_indexes"}:
                raise ValueError(f"{where}: malformed static target candidate {candidate_index}")
            target = _address_value(candidate["target_address"], where=f"{where}.candidate[{candidate_index}]")
            indexes = candidate["alternative_indexes"]
            if (
                not isinstance(indexes, list) or not indexes
                or any(type(index) is not int for index in indexes)
                or len(indexes) != len(set(indexes))
            ):
                raise ValueError(f"{where}: malformed candidate alternative indexes")
            for index in indexes:
                if not 1 <= index <= len(alternatives):
                    raise ValueError(f"{where}: candidate alternative index is out of range")
                alternative = alternatives[index - 1]
                if not isinstance(alternative, dict) or alternative.get("status") != "resolved" or alternative.get("root_kind") != "address_anchor":
                    raise ValueError(f"{where}: candidate does not reference a resolved address anchor")
                root = _CONST_ANCHOR.fullmatch(alternative.get("root_id", ""))
                size = alternative.get("pointer_size_bytes")
                offset = alternative.get("offset_bytes")
                if root is None or size != 4 or type(offset) is not int or int(root.group(2)) != size:
                    raise ValueError(f"{where}: candidate source is not a 32-bit constant address anchor")
                if (int(root.group(1), 16) + offset) % (1 << 32) != target:
                    raise ValueError(f"{where}: candidate target disagrees with its address anchor")
            identity = (*site, target)
            if identity in seen:
                raise ValueError(f"{where}: duplicate triage target for one CALLIND site")
            seen.add(identity)
            by_site.setdefault(site, []).append({
                "target_address": f"0x{target:08x}",
                "resolution_scope": TARGET_TRIAGE_SCOPE,
                "evidence_state": evidence_state,
                "program_sha256": program_sha256,
                "source": {
                    "artifact_path": path.as_posix(),
                    "artifact_sha256": artifact_sha256,
                    "record_index": record_index,
                    "target_candidate_index": candidate_index,
                    "source_format": TARGET_TRIAGE_FORMAT,
                },
            })
        covered = {
            index
            for candidate in candidates
            for index in candidate["alternative_indexes"]
        }
        expected_scope = (
            "bounded_static_target_candidates"
            if covered == set(range(1, len(alternatives) + 1))
            else "partial_static_target_candidates"
        )
        if candidate_scope != expected_scope:
            raise ValueError(f"{where}: candidate scope disagrees with covered provenance alternatives")
    for observations in by_site.values():
        observations.sort(key=_target_observation_key)
    return artifact_sha256, by_site


def build_direct_call_memory_effect_closure(
    program_id: str,
    caller_flow_tsv: Path,
    *,
    callee_flows: list[tuple[str, Path]] | None = None,
    max_calls: int = MAX_CALLS,
    max_flow_bytes: int = MAX_FLOW_BYTES,
    max_flow_operations: int = MAX_FLOW_OPERATIONS,
    max_functions: int = MAX_FUNCTIONS,
    max_closure_visits: int = MAX_CLOSURE_VISITS,
    static_indirect_call_targets: Path | None = None,
    indirect_call_vtable_candidates: list[Path] | None = None,
    indirect_call_target_triage: Path | None = None,
    program_sha256: str | None = None,
) -> list[dict[str, Any]]:
    """Summarize each caller call using a closed, cycle-safe direct-call graph.

    A row is write-free only when every reachable function has a complete flow,
    contains no STORE or unknown operation, and every nested direct call is
    resolved by the supplied flow set. Cycles terminate through the visited-set
    walk; indirect calls and missing nested flows remain barriers. Optional
    target evidence annotates exact CALLIND sites without resolving them.
    """
    if not program_id:
        raise ValueError("program_id must be non-empty")
    if max_calls < 1:
        raise ValueError("max_calls must be positive")
    if min(max_flow_bytes, max_flow_operations, max_functions, max_closure_visits) < 1:
        raise ValueError("P-code flow budgets must be positive")
    target_evidence_paths = [
        *([static_indirect_call_targets] if static_indirect_call_targets is not None else []),
        *(indirect_call_vtable_candidates or []),
        *([indirect_call_target_triage] if indirect_call_target_triage is not None else []),
    ]
    if len({path.resolve() for path in target_evidence_paths}) != len(target_evidence_paths):
        raise ValueError("duplicate indirect target evidence input")
    if sum(path.stat().st_size for path in target_evidence_paths) > MAX_TARGET_EVIDENCE_BYTES:
        raise ValueError(f"target evidence byte budget exceeded: {MAX_TARGET_EVIDENCE_BYTES}")
    if not target_evidence_paths:
        if program_sha256 is not None:
            raise ValueError("--program-sha256 requires indirect target evidence")
        target_evidence_hashes = []
        target_observations_by_site = {}
    else:
        if program_sha256 is None or _SHA256.fullmatch(program_sha256) is None:
            raise ValueError("indirect target evidence requires a lowercase --program-sha256")
        target_evidence_hashes = []
        target_observations_by_site = {}
        if static_indirect_call_targets is not None:
            evidence_sha256, targets = _read_static_targets(
                static_indirect_call_targets,
                program_id=program_id,
                program_sha256=program_sha256,
            )
            target_evidence_hashes.append(evidence_sha256)
            for site, observations in targets.items():
                target_observations_by_site.setdefault(site, []).extend(observations)
        if indirect_call_target_triage is not None:
            evidence_sha256, targets = _read_target_triage(
                indirect_call_target_triage,
                program_id=program_id,
                program_sha256=program_sha256,
            )
            target_evidence_hashes.append(evidence_sha256)
            for site, observations in targets.items():
                target_observations_by_site.setdefault(site, []).extend(observations)
        for candidate_path in indirect_call_vtable_candidates or []:
            evidence_sha256, targets = _read_vtable_candidates(
                candidate_path,
                program_id=program_id,
                program_sha256=program_sha256,
            )
            target_evidence_hashes.append(evidence_sha256)
            for site, observations in targets.items():
                target_observations_by_site.setdefault(site, []).extend(observations)
        for observations in target_observations_by_site.values():
            observations.sort(key=_target_observation_key)

    callee_flows = callee_flows or []
    paths = [caller_flow_tsv, *(path for _, path in callee_flows)]
    if sum(path.stat().st_size for path in paths) > max_flow_bytes:
        raise ValueError(f"P-code flow byte budget exceeded: {max_flow_bytes}")

    caller_sha, caller_rows = _read_pcode_flow(
        caller_flow_tsv, max_operations=max_flow_operations
    )
    caller_entry = caller_rows[0]["function_entry"]
    available = _read_callee_flows(callee_flows, max_operations=max_flow_operations)
    caller_flow = (caller_sha, caller_rows)
    if caller_entry in available:
        if available[caller_entry][0] != caller_sha:
            raise ValueError("callee flow for caller entry conflicts with caller input")
        del available[caller_entry]
    flows = {caller_entry: caller_flow, **available}
    if len(flows) > max_functions:
        raise ValueError(f"P-code flow function budget exceeded: {max_functions}")
    if sum(len(rows) for _, rows in flows.values()) > max_flow_operations:
        raise ValueError(f"P-code flow operation budget exceeded: {max_flow_operations}")

    caller_calls = [
        (index, row)
        for index, row in enumerate(caller_rows, 1)
        if row["opcode"] in {"CALL", "CALLIND"}
    ]
    if not caller_calls:
        raise ValueError("caller P-code flow contains no CALL or CALLIND operations")

    reachable_union: set[str] = set()
    total_call_sites = sum(
        row["opcode"] in {"CALL", "CALLIND"}
        for _, rows in flows.values()
        for row in rows
    )
    if total_call_sites > max_calls:
        raise ValueError(f"direct call memory effect budget exceeded: {max_calls}")

    summaries: dict[str, tuple[set[str], set[str], int]] = {}
    closure_visits = 0

    def summarize(entry: str) -> tuple[set[str], set[str], int]:
        nonlocal closure_visits
        if entry not in summaries:
            summary = _closure_summary(entry, flows)
            closure_visits += len(summary[0])
            if closure_visits > max_closure_visits:
                raise ValueError(f"call closure visit budget exceeded: {max_closure_visits}")
            summaries[entry] = summary
        return summaries[entry]

    closure_output_entries = 0
    for _, row in caller_calls:
        target = row.get("callee_entry", "-")
        if row["opcode"] == "CALL" and target not in {"", "-"} and target in flows:
            reachable, _, _ = summarize(target)
            reachable_union.update(reachable)
            closure_output_entries += len(reachable)
            if closure_visits + closure_output_entries > max_closure_visits:
                raise ValueError(f"call closure visit budget exceeded: {max_closure_visits}")
    unused = set(available) - reachable_union
    if unused:
        raise ValueError(f"callee flows are not reachable from caller P-code: {sorted(unused)}")

    result = []
    output_format = FORMAT_V2 if target_evidence_hashes else FORMAT_V1
    matched_target_observations = 0
    for record_index, row in caller_calls:
        opcode = row["opcode"]
        callee_entry = row.get("callee_entry") if opcode == "CALL" and row.get("callee_entry") != "-" else None
        callee_flow = flows.get(callee_entry) if callee_entry is not None else None
        callee_sha = None if callee_flow is None else callee_flow[0]
        callee_rows = [] if callee_flow is None else callee_flow[1]
        closure_sha = None
        closure_entries: list[str] = []
        closure_calls = 0
        if opcode == "CALLIND":
            status, effect_opcodes = "indirect_call", []
        elif callee_entry is None:
            status, effect_opcodes = "unresolved_target", []
        elif callee_flow is None:
            status, effect_opcodes = "missing_callee_flow", []
        else:
            reachable, effects, closure_calls = summarize(callee_entry)
            closure_entries = sorted(reachable)
            closure_sha = _closure_digest(reachable, flows)
            effect_opcodes = sorted(effects)
            if "STORE" in effects:
                status = "explicit_memory_write"
            elif effects:
                status = "unknown_effect"
            else:
                status = "no_explicit_memory_write"
        provenance = {
            "caller_pcode_flow_sha256": caller_sha,
            "caller_pcode_flow_record_index": record_index,
            "callee_pcode_flow_sha256": callee_sha,
            "callee_pcode_flow_record_count": len(callee_rows),
            "closure_sha256": closure_sha,
            "closure_function_entries": closure_entries,
            "closure_call_site_count": closure_calls,
        }
        if opcode == "CALLIND":
            site = (
                _address_value(row["function_entry"], where="P-code function entry"),
                _address_value(row["op_address"], where="P-code call address"),
                int(row["op_time"]),
            )
            observations = target_observations_by_site.get(site, [])
            if observations:
                provenance["indirect_target_observations"] = observations
                matched_target_observations += len(observations)
        result.append({
            "format": output_format,
            "program_id": program_id,
            "function_entry": caller_entry,
            "address": row["op_address"],
            "time": int(row["op_time"]),
            "opcode": opcode,
            "callee_entry": callee_entry,
            "status": status,
            "effect_opcodes": effect_opcodes,
            "provenance": provenance,
        })
    if target_evidence_hashes and matched_target_observations == 0:
        raise ValueError("indirect target evidence has no exact CALLIND site in caller P-code flow")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("caller_pcode_flow", type=Path)
    parser.add_argument("--program-id", required=True, help="Opaque consumer join key.")
    parser.add_argument(
        "--callee-flow", action="append", nargs=2, metavar=("ENTRY", "TSV"),
        default=[], help="One-function P-code flow in the transitive direct-call closure; repeat as needed.",
    )
    parser.add_argument("--max-calls", type=int, default=MAX_CALLS)
    parser.add_argument("--max-flow-bytes", type=int, default=MAX_FLOW_BYTES)
    parser.add_argument("--max-flow-operations", type=int, default=MAX_FLOW_OPERATIONS)
    parser.add_argument("--max-functions", type=int, default=MAX_FUNCTIONS)
    parser.add_argument("--max-closure-visits", type=int, default=MAX_CLOSURE_VISITS)
    parser.add_argument(
        "--static-indirect-call-targets", type=Path,
        help="optional GhidraStaticIndirectCallTarget/1 JSONL; joins exact CALLIND sites but preserves the indirect-call barrier",
    )
    parser.add_argument(
        "--indirect-call-vtable-candidates", type=Path, action="append", default=[],
        help="GhidraIndirectCallVtableCandidates/1 JSONL; repeat to join multiple candidate artifacts at exact CALLIND sites",
    )
    parser.add_argument(
        "--indirect-call-target-triage", type=Path,
        help="IndirectCallTargetTriage/1 JSONL; joins constant-address provenance candidates at exact CALLIND sites",
    )
    parser.add_argument(
        "--program-sha256",
        help="required with indirect target evidence; SHA-256 of the analyzed binary",
    )
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    rows = build_direct_call_memory_effect_closure(
        args.program_id,
        args.caller_pcode_flow,
        callee_flows=[(entry, Path(path)) for entry, path in args.callee_flow],
        max_calls=args.max_calls,
        max_flow_bytes=args.max_flow_bytes,
        max_flow_operations=args.max_flow_operations,
        max_functions=args.max_functions,
        max_closure_visits=args.max_closure_visits,
        static_indirect_call_targets=args.static_indirect_call_targets,
        indirect_call_vtable_candidates=args.indirect_call_vtable_candidates,
        indirect_call_target_triage=args.indirect_call_target_triage,
        program_sha256=args.program_sha256,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["status"]] = counts.get(row["status"], 0) + 1
    print("call sites:", len(rows))
    print("status counts:", json.dumps(counts, sort_keys=True))
    if args.static_indirect_call_targets is not None or args.indirect_call_vtable_candidates or args.indirect_call_target_triage is not None:
        observations = [
            observation
            for row in rows
            for observation in row["provenance"].get("indirect_target_observations", [])
        ]
        print("indirect target observations:", len(observations))
        print("target evidence SHA-256:", json.dumps(sorted({
            observation["source"]["artifact_sha256"] for observation in observations
        })))
    print("output:", args.output)
    return 0
