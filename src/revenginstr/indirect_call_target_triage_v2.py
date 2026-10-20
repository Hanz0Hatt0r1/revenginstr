"""Attach evidence-backed symbolic names to exact indirect-call triage sites."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

TRIAGE_V1 = "REVENGINSTR.IndirectCallTargetTriage/1"
SYMBOL_CANDIDATES = "REVENGINSTR.GhidraIndirectCallSymbolCandidates/1"
FORMAT = "REVENGINSTR.IndirectCallTargetTriage/2"
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
ADDRESS_RE = re.compile(r"^(?:(?P<space>[A-Za-z_$][\w$]*):)?(?:0x)?(?P<offset>[0-9a-fA-F]+)$")
MAX_ROWS = 1_000_000
TRIAGE_FIELDS = {
    "format", "program_id", "program_sha256", "function_entry", "call_address", "call_time",
    "provenance_status", "classification", "bounded_path_count", "dynamic_barrier_count",
    "limited_path_count", "alternatives", "static_target_candidate_scope", "static_target_candidates",
    "pcode_operation", "callind_evidence", "source",
}


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-JSON numeric constant {value}")


def _read_jsonl(path: Path, *, max_rows: int) -> tuple[str, list[tuple[int, dict[str, Any]]]]:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            hasher.update(block)
    digest = hasher.hexdigest()
    rows: list[tuple[int, dict[str, Any]]] = []
    with path.open("r", encoding="utf-8", newline="") as handle:
        for line_no, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            if len(rows) >= max_rows:
                raise ValueError(f"{path}: row budget exceeded: {max_rows}")
            try:
                row = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
            except ValueError as error:
                raise ValueError(f"{path}:{line_no}: invalid JSON: {error}") from error
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_no}: expected a JSON object")
            rows.append((line_no, row))
    return digest, rows


def _address_key(value: Any, where: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{where}: expected an address string")
    match = ADDRESS_RE.fullmatch(value)
    if match is None:
        raise ValueError(f"{where}: invalid address {value!r}")
    space = match.group("space")
    return f"{space.lower() + ':' if space else ''}0x{int(match.group('offset'), 16):x}"


def _site_key(row: dict[str, Any], where: str) -> tuple[str, str, int]:
    entry = _address_key(row.get("function_entry"), f"{where}.function_entry")
    call = _address_key(row.get("call_address"), f"{where}.call_address")
    call_time = row.get("call_time")
    if type(call_time) is not int or call_time < 0:
        raise ValueError(f"{where}: call_time must be a non-negative integer")
    return entry, call, call_time


def _evidence_ref(value: Any, where: str) -> dict[str, Any]:
    fields = {"source_format", "artifact_path", "artifact_sha256", "record_index"}
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{where}: malformed evidence reference")
    if not isinstance(value["source_format"], str) or not value["source_format"]:
        raise ValueError(f"{where}: invalid source_format")
    if not isinstance(value["artifact_path"], str) or not value["artifact_path"]:
        raise ValueError(f"{where}: invalid artifact_path")
    if not isinstance(value["artifact_sha256"], str) or SHA256_RE.fullmatch(value["artifact_sha256"]) is None:
        raise ValueError(f"{where}: invalid artifact_sha256")
    if type(value["record_index"]) is not int or value["record_index"] < 1:
        raise ValueError(f"{where}: invalid record_index")
    return value


def _symbolic_candidate(value: Any, alternative_count: int, where: str) -> dict[str, Any]:
    fields = {
        "candidate_kind", "module", "symbol", "address", "alternative_indexes", "evidence_refs", "limitations",
    }
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError(f"{where}: malformed symbolic candidate fields")
    kind = value["candidate_kind"]
    if not isinstance(kind, str) or kind not in {"external_api", "internal_function"}:
        raise ValueError(f"{where}: unsupported candidate_kind {kind!r}")
    for name in ("module", "symbol"):
        if not isinstance(value[name], str) or not value[name].strip():
            raise ValueError(f"{where}: {name} must be non-empty")
    address = value["address"]
    if kind == "external_api" and address is not None:
        raise ValueError(f"{where}: an external API must not claim a static address")
    if kind == "internal_function":
        _address_key(address, f"{where}.address")
    indexes = value["alternative_indexes"]
    if (
        not isinstance(indexes, list) or not indexes
        or any(type(index) is not int or not 1 <= index <= alternative_count for index in indexes)
        or len(indexes) != len(set(indexes))
    ):
        raise ValueError(f"{where}: invalid alternative_indexes")
    refs = value["evidence_refs"]
    if not isinstance(refs, list) or not refs:
        raise ValueError(f"{where}: at least one evidence_ref is required")
    for ref in refs:
        _evidence_ref(ref, f"{where}.evidence_refs")
    limitations = value["limitations"]
    if (
        not isinstance(limitations, list) or not limitations
        or any(not isinstance(item, str) or not item for item in limitations)
        or len(limitations) != len(set(limitations))
    ):
        raise ValueError(f"{where}: limitations must be non-empty unique strings")
    return value


def build_symbolic_indirect_call_target_triage(
    triage_path: Path, symbolic_candidate_paths: list[Path], *, max_rows: int = MAX_ROWS,
) -> list[dict[str, Any]]:
    """Enrich v1 CALLIND rows; unmatched or ambiguous site joins fail closed."""
    if type(max_rows) is not int or max_rows < 1:
        raise ValueError("max_rows must be a positive integer")
    if not symbolic_candidate_paths:
        raise ValueError("at least one symbolic candidate JSONL input is required")
    _, triage_records = _read_jsonl(triage_path, max_rows=max_rows)
    by_site: dict[tuple[str, str, int], dict[str, Any]] = {}
    ordered: list[tuple[dict[str, Any], tuple[str, str, int]]] = []
    for line_no, row in triage_records:
        where = f"{triage_path}:{line_no}"
        if set(row) != TRIAGE_FIELDS or row.get("format") != TRIAGE_V1:
            raise ValueError(f"{where}: expected {TRIAGE_V1} with exact fields")
        if not isinstance(row.get("program_id"), str) or not row["program_id"]:
            raise ValueError(f"{where}: program_id must be non-empty")
        if not isinstance(row.get("program_sha256"), str) or SHA256_RE.fullmatch(row["program_sha256"]) is None:
            raise ValueError(f"{where}: invalid program_sha256")
        alternatives = row.get("alternatives")
        if not isinstance(alternatives, list) or not alternatives:
            raise ValueError(f"{where}: alternatives must be a non-empty array")
        site = _site_key(row, where)
        if site in by_site:
            raise ValueError(f"{where}: duplicate CALLIND site {site!r}")
        by_site[site] = row
        ordered.append((row, site))
    if not ordered:
        raise ValueError(f"{triage_path}: no triage rows")

    annotations: dict[tuple[str, str, int], tuple[list[dict[str, Any]], dict[str, Any]]] = {}
    total_rows = 0
    for path in symbolic_candidate_paths:
        digest, records = _read_jsonl(path, max_rows=max_rows)
        for line_no, row in records:
            total_rows += 1
            where = f"{path}:{line_no}"
            if total_rows > max_rows:
                raise ValueError(f"combined symbolic input row budget exceeded: {max_rows}")
            if set(row) != {
                "format", "program_id", "program_sha256", "function_entry", "call_address", "call_time", "candidates",
            } or row.get("format") != SYMBOL_CANDIDATES:
                raise ValueError(f"{where}: expected {SYMBOL_CANDIDATES} with exact fields")
            site = _site_key(row, where)
            triage = by_site.get(site)
            if triage is None:
                raise ValueError(f"{where}: no exact CALLIND triage site match")
            if row.get("program_id") != triage["program_id"] or row.get("program_sha256") != triage["program_sha256"]:
                raise ValueError(f"{where}: analyzed-program identity does not match triage row")
            if site in annotations:
                raise ValueError(f"{where}: duplicate symbolic candidates for site {site!r}")
            candidates = row.get("candidates")
            if not isinstance(candidates, list) or not candidates:
                raise ValueError(f"{where}: candidates must be a non-empty array")
            identities: set[tuple[Any, ...]] = set()
            for index, candidate in enumerate(candidates, 1):
                candidate = _symbolic_candidate(candidate, len(triage["alternatives"]), f"{where}.candidates[{index}]")
                identity = tuple(candidate[field] for field in ("candidate_kind", "module", "symbol", "address"))
                if identity in identities:
                    raise ValueError(f"{where}: duplicate symbolic target {identity!r}")
                identities.add(identity)
            annotations[site] = (candidates, {
                "source_format": SYMBOL_CANDIDATES,
                "artifact_path": str(path),
                "artifact_sha256": digest,
                "record_index": line_no,
            })

    rows = []
    for original, site in ordered:
        candidates, source = annotations.get(site, ([], None))
        rows.append({
            **original,
            "format": FORMAT,
            "symbolic_target_candidates": candidates,
            "symbolic_target_source": source,
        })
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-triage", type=Path, required=True, help="IndirectCallTargetTriage/1 JSONL")
    parser.add_argument("--symbolic-candidates", type=Path, action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--max-rows", type=int, default=MAX_ROWS)
    args = parser.parse_args(argv)
    rows = build_symbolic_indirect_call_target_triage(
        args.target_triage, args.symbolic_candidates, max_rows=args.max_rows,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    print("output rows:", len(rows))
    print("symbolically annotated rows:", sum(bool(row["symbolic_target_candidates"]) for row in rows))
    print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
