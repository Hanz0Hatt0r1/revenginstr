"""Summarize which indirect-call target paths remain blocked by provenance barriers."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any, Iterator

FORMAT = "REVENGINSTR.IndirectCallTargetTriage/1"
PROVENANCE_FORMAT = "REVENGINSTR.PointerProvenance/1"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ADDRESS_RE = re.compile(r"^(?:(?P<space>[A-Za-z_$][\w$]*):)?(?:0x)?(?P<offset>[0-9a-fA-F]+)$")
CONSTANT_ANCHOR_RE = re.compile(r"^const:(0x[0-9a-fA-F]+):(?P<size>[0-9]+)$")
MAX_ROWS = 1_000_000
STRUCTURAL_STATUSES = {"resolved", "load_anchor"}
DYNAMIC_BARRIERS = {"call_barrier", "indirect_barrier"}
LIMIT_STATUSES = {
    "cycle", "depth_limit", "alternative_limit", "unsupported_opcode", "dynamic_offset",
    "offset_overflow", "width_mismatch", "missing_definition",
}
PROVENANCE_STATUSES = STRUCTURAL_STATUSES | DYNAMIC_BARRIERS | LIMIT_STATUSES | {"ambiguous", "unknown"}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-JSON numeric constant {value}")


def _address_key(value: str) -> str:
    match = ADDRESS_RE.fullmatch(value)
    if match is None:
        raise ValueError(f"unsupported address {value!r}")
    space = match.group("space")
    return f"{space.lower() + ':' if space else ''}0x{int(match.group('offset'), 16):x}"


def _evidence_ref(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "source_format", "artifact_path", "artifact_sha256", "record_index",
    }:
        raise ValueError(f"{where}: invalid evidence reference")
    if not isinstance(value["source_format"], str) or not value["source_format"]:
        raise ValueError(f"{where}: invalid source_format")
    if not isinstance(value["artifact_path"], str) or not value["artifact_path"]:
        raise ValueError(f"{where}: invalid artifact_path")
    if not isinstance(value["artifact_sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", value["artifact_sha256"]):
        raise ValueError(f"{where}: invalid artifact_sha256")
    index = value["record_index"]
    if isinstance(index, bool) or not isinstance(index, int) or index < 1:
        raise ValueError(f"{where}: invalid record_index")
    return value


def _read_jsonl(path: Path, *, max_rows: int) -> Iterator[tuple[int, dict[str, Any]]]:
    count = 0
    with path.open("r", encoding="utf-8", newline="") as handle:
        for line_no, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            count += 1
            if count > max_rows:
                raise ValueError(f"{path}: row budget exceeded: {max_rows}")
            try:
                row = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
            except ValueError as error:
                raise ValueError(f"{path}:{line_no}: invalid JSON: {error}") from error
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_no}: expected a JSON object")
            yield line_no, row


def _classify(alternatives: list[dict[str, Any]]) -> tuple[str, int, int, int]:
    statuses = [item["status"] for item in alternatives]
    bounded = sum(status in STRUCTURAL_STATUSES for status in statuses)
    blocked = sum(status in DYNAMIC_BARRIERS for status in statuses)
    limited = sum(status in LIMIT_STATUSES for status in statuses)
    if limited:
        classification = "analysis_limited"
    elif bounded and blocked:
        classification = "mixed_bounded_and_blocked"
    elif bounded and any(status not in STRUCTURAL_STATUSES for status in statuses):
        classification = "mixed_bounded_and_unresolved"
    elif blocked:
        classification = "dynamic_barrier_only"
    elif bounded:
        classification = "bounded_provenance_only"
    else:
        classification = "unresolved"
    return classification, bounded, blocked, limited


def _static_target_candidates(alternatives: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    by_target: dict[str, list[int]] = {}
    for index, alternative in enumerate(alternatives, 1):
        if alternative["status"] != "resolved" or alternative["root_kind"] != "address_anchor":
            continue
        root = CONSTANT_ANCHOR_RE.fullmatch(alternative["root_id"])
        size = alternative["pointer_size_bytes"]
        offset = alternative["offset_bytes"]
        if root is None or isinstance(size, bool) or not isinstance(size, int) or size < 1:
            continue
        if int(root.group("size")) != size or isinstance(offset, bool) or not isinstance(offset, int):
            continue
        target = (int(root.group(1), 16) + offset) % (1 << (size * 8))
        if target == 0:
            continue
        address = f"0x{target:0{size * 2}x}"
        by_target.setdefault(address, []).append(index)
    if not by_target:
        return "none", []
    candidates = [
        {"target_address": address, "alternative_indexes": indexes}
        for address, indexes in sorted(by_target.items())
    ]
    covered = {index for indexes in by_target.values() for index in indexes}
    scope = "bounded_static_target_candidates" if len(covered) == len(alternatives) else "partial_static_target_candidates"
    return scope, candidates


def build_indirect_call_target_triage(
    paths: list[Path], *, program_id: str, program_sha256: str, max_rows: int = MAX_ROWS,
) -> list[dict[str, Any]]:
    """Create a source-pinned diagnosis for each exact CALLIND provenance record."""
    if not program_id:
        raise ValueError("program_id must be non-empty")
    if not isinstance(program_sha256, str) or SHA256_RE.fullmatch(program_sha256) is None:
        raise ValueError("program_sha256 must be a lowercase SHA-256")
    if isinstance(max_rows, bool) or not isinstance(max_rows, int) or max_rows < 1:
        raise ValueError("max_rows must be positive")
    if not paths:
        raise ValueError("at least one PointerProvenance/1 JSONL input is required")

    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, int]] = set()
    total_rows = 0
    for path in paths:
        digest = _sha256(path)
        for line_no, row in _read_jsonl(path, max_rows=max_rows):
            total_rows += 1
            if total_rows > max_rows:
                raise ValueError(f"combined input row budget exceeded: {max_rows}")
            where = f"{path}:{line_no}"
            if row.get("format") != PROVENANCE_FORMAT:
                raise ValueError(f"{where}: expected {PROVENANCE_FORMAT}")
            if set(row) != {
                "format", "record_kind", "evidence_class", "program_id", "function_entry",
                "operation_address", "operation_time", "opcode", "output_token", "status",
                "alternatives", "load_address", "source", "target_source",
            }:
                raise ValueError(f"{where}: unexpected PointerProvenance/1 fields")
            if row.get("program_id") != program_id:
                raise ValueError(f"{where}: program_id does not match {program_id!r}")
            if row.get("record_kind") != "callind_target":
                continue
            if row.get("evidence_class") != "derived_structural" or row.get("opcode") != "CALLIND":
                raise ValueError(f"{where}: invalid CALLIND provenance record")
            function_entry = row.get("function_entry")
            call_address = row.get("operation_address")
            call_time = row.get("operation_time")
            if not isinstance(function_entry, str) or ADDRESS_RE.fullmatch(function_entry) is None:
                raise ValueError(f"{where}: invalid function_entry")
            if not isinstance(call_address, str) or ADDRESS_RE.fullmatch(call_address) is None:
                raise ValueError(f"{where}: invalid operation_address")
            if isinstance(call_time, bool) or not isinstance(call_time, int) or call_time < 0:
                raise ValueError(f"{where}: invalid operation_time")
            if row.get("status") not in PROVENANCE_STATUSES:
                raise ValueError(f"{where}: unsupported provenance status {row.get('status')!r}")
            alternatives = row.get("alternatives")
            if not isinstance(alternatives, list) or not alternatives:
                raise ValueError(f"{where}: alternatives must be a non-empty array")
            for alternative in alternatives:
                if not isinstance(alternative, dict) or set(alternative) != {
                    "root_kind", "evidence_class", "root_id", "offset_bytes", "pointer_size_bytes",
                    "address_space_token", "status", "transformation_path", "evidence_refs",
                } or alternative.get("status") not in PROVENANCE_STATUSES:
                    raise ValueError(f"{where}: malformed provenance alternative")
                if not isinstance(alternative["transformation_path"], list) or not isinstance(alternative["evidence_refs"], list):
                    raise ValueError(f"{where}: malformed alternative lineage")
                for evidence_ref in alternative["evidence_refs"]:
                    _evidence_ref(evidence_ref, where)

            identity = (_address_key(function_entry), _address_key(call_address), call_time)
            if identity in seen:
                raise ValueError(f"{where}: duplicate CALLIND provenance site {identity!r}")
            seen.add(identity)
            classification, bounded_count, barrier_count, limited_count = _classify(alternatives)
            candidate_scope, target_candidates = _static_target_candidates(alternatives)
            rows.append({
                "format": FORMAT,
                "program_id": program_id,
                "program_sha256": program_sha256,
                "function_entry": function_entry,
                "call_address": call_address,
                "call_time": call_time,
                "provenance_status": row["status"],
                "classification": classification,
                "bounded_path_count": bounded_count,
                "dynamic_barrier_count": barrier_count,
                "limited_path_count": limited_count,
                "alternatives": alternatives,
                "static_target_candidate_scope": candidate_scope,
                "static_target_candidates": target_candidates,
                "pcode_operation": _evidence_ref(row["source"], f"{where}: source"),
                "callind_evidence": _evidence_ref(row["target_source"], f"{where}: target_source"),
                "source": {
                    "source_format": PROVENANCE_FORMAT,
                    "artifact_path": str(path),
                    "artifact_sha256": digest,
                    "record_index": line_no,
                },
            })
    if not rows:
        raise ValueError("no CALLIND provenance records found")
    return sorted(rows, key=lambda row: (row["function_entry"].lower(), row["call_address"].lower(), row["call_time"]))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--program-id", required=True)
    parser.add_argument("--program-sha256", required=True)
    parser.add_argument("--pointer-provenance", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-rows", type=int, default=MAX_ROWS)
    args = parser.parse_args(argv)
    rows = build_indirect_call_target_triage(
        args.pointer_provenance, program_id=args.program_id,
        program_sha256=args.program_sha256, max_rows=args.max_rows,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    print("output rows:", len(rows))
    print("classifications:", dict(sorted(Counter(row["classification"] for row in rows).items())))
    print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
