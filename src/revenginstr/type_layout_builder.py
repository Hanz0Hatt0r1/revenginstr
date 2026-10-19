"""Build conservative type-layout candidates from exact stores and reviewed memberships."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterable, Iterator

STORE_FORMAT = "REVENGINSTR.GhidraMemoryStoreAccess/1"
MEMBER_FORMAT = "REVENGINSTR.TypeLayoutMemberMap/1"
SIZE_REVIEW_FORMAT = "REVENGINSTR.TypeLayoutSizeReview/1"
LOAD_FORMAT = "REVENGINSTR.GhidraParameterLoadField/1"
OUTPUT_FORMAT = "REVENGINSTR.TypeLayoutHypothesis/1"
LOAD_COLUMNS = (
    "format", "function_entry", "function_name", "load_address", "load_time",
    "base_parameter_index", "field_offset", "address_pattern", "value_size",
    "value_token", "status",
)
STORE_KEYS = {
    "format", "program_id", "function_entry", "address", "time", "opcode",
    "memory_space", "memory_physical_space", "memory_width_bytes",
    "memory_pointer_width_bytes", "memory_space_size_bits",
    "memory_addressable_unit_bytes", "pointer_token", "root_parameter_index",
    "offset_bytes", "location_status", "destination_pattern", "address_expression_ops",
}
MEMBER_KEYS = {
    "format", "program_id", "program_sha256", "type_id", "function_entry",
    "root_parameter_index",
}
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
DEFAULT_MAX_ROWS = 1_000_000


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


def _read_jsonl(path: Path, *, max_rows: int) -> Iterator[tuple[int, dict[str, Any]]]:
    count = 0
    with path.open("r", encoding="utf-8", newline="") as handle:
        for line_no, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            count += 1
            if count > max_rows:
                raise ValueError(f"{path}: input row budget exceeded: {max_rows}")
            try:
                row = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
            except ValueError as error:
                raise ValueError(f"{path}:{line_no}: invalid JSON: {error}") from error
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_no}: expected a JSON object")
            yield line_no, row


def _require_text(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{where}: expected a non-empty string")
    return value


def _require_int(value: Any, where: str, *, minimum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or (minimum is not None and value < minimum):
        suffix = f" >= {minimum}" if minimum is not None else ""
        raise ValueError(f"{where}: expected integer{suffix}")
    return value


def _parse_decimal(value: str, where: str, *, minimum: int = 0) -> int:
    if not re.fullmatch(r"[0-9]+", value):
        raise ValueError(f"{where}: expected decimal integer")
    parsed = int(value)
    if parsed < minimum:
        raise ValueError(f"{where}: expected integer >= {minimum}")
    return parsed


def _nullable_positive_int(value: Any, where: str) -> int | None:
    if value is None:
        return None
    return _require_int(value, where, minimum=1)


def _evidence(
    *, source_format: str, source_sha256: str, record_key: str, evidence_class: str,
) -> dict[str, str]:
    return {
        "source_format": source_format,
        "source_sha256": source_sha256,
        "record_key": record_key,
        "evidence_class": evidence_class,
    }


def _sort_evidence(items: Iterable[dict[str, str]]) -> list[dict[str, str]]:
    unique = {
        (
            item["source_format"], item["source_sha256"], item["record_key"],
            item.get("source_pointer", ""), item["evidence_class"],
        ): item
        for item in items
    }
    return [unique[key] for key in sorted(unique)]


def _validate_store(row: dict[str, Any], where: str, *, program_id: str) -> None:
    if set(row) != STORE_KEYS or row.get("format") != STORE_FORMAT:
        raise ValueError(f"{where}: expected exact {STORE_FORMAT} fields")
    if _require_text(row["program_id"], f"{where}: program_id") != program_id:
        raise ValueError(f"{where}: program_id does not match {program_id!r}")
    _require_text(row["function_entry"], f"{where}: function_entry")
    _require_text(row["address"], f"{where}: address")
    _require_int(row["time"], f"{where}: time", minimum=0)
    if row["opcode"] != "STORE":
        raise ValueError(f"{where}: opcode must be STORE")
    for key in ("memory_space", "memory_physical_space"):
        if row[key] is not None:
            _require_text(row[key], f"{where}: {key}")
    for key in (
        "memory_width_bytes", "memory_pointer_width_bytes", "memory_space_size_bits",
        "memory_addressable_unit_bytes",
    ):
        _nullable_positive_int(row[key], f"{where}: {key}")
    _require_text(row["pointer_token"], f"{where}: pointer_token")
    if row["root_parameter_index"] is not None:
        _require_int(row["root_parameter_index"], f"{where}: root_parameter_index", minimum=0)
    if row["offset_bytes"] is not None:
        _require_int(row["offset_bytes"], f"{where}: offset_bytes")
    if row["location_status"] not in ("parameter_rooted_constant_offset", "unresolved"):
        raise ValueError(f"{where}: unsupported location_status")
    _require_text(row["destination_pattern"], f"{where}: destination_pattern")
    if not isinstance(row["address_expression_ops"], list):
        raise ValueError(f"{where}: address_expression_ops must be an array")
    for index, operation in enumerate(row["address_expression_ops"]):
        op_where = f"{where}: address_expression_ops[{index}]"
        if not isinstance(operation, dict) or set(operation) != {"address", "time", "opcode"}:
            raise ValueError(f"{op_where}: expected exact address/time/opcode fields")
        _require_text(operation["address"], f"{op_where}: address")
        _require_int(operation["time"], f"{op_where}: time", minimum=0)
        _require_text(operation["opcode"], f"{op_where}: opcode")
    if row["location_status"] == "parameter_rooted_constant_offset":
        if row["root_parameter_index"] is None or row["offset_bytes"] is None:
            raise ValueError(f"{where}: resolved location requires root and offset")
        for key in (
            "memory_space", "memory_width_bytes", "memory_pointer_width_bytes",
            "memory_space_size_bits", "memory_addressable_unit_bytes",
        ):
            if row[key] is None:
                raise ValueError(f"{where}: resolved location requires {key}")


def _validate_member(
    row: dict[str, Any], where: str, *, program_id: str, program_sha256: str,
) -> tuple[str, int, str]:
    if set(row) != MEMBER_KEYS or row.get("format") != MEMBER_FORMAT:
        raise ValueError(f"{where}: expected exact {MEMBER_FORMAT} fields")
    if _require_text(row["program_id"], f"{where}: program_id") != program_id:
        raise ValueError(f"{where}: program_id does not match {program_id!r}")
    if row["program_sha256"] != program_sha256:
        raise ValueError(f"{where}: program_sha256 does not match the pinned program")
    type_id = _require_text(row["type_id"], f"{where}: type_id")
    function_entry = _require_text(row["function_entry"], f"{where}: function_entry")
    root_index = _require_int(row["root_parameter_index"], f"{where}: root_parameter_index", minimum=0)
    return function_entry, root_index, type_id


def _validate_size_review(
    row: dict[str, Any], where: str, *, program_id: str, program_sha256: str,
) -> tuple[str, int, dict[str, str]]:
    keys = {"format", "program_id", "program_sha256", "type_id", "exact_size_bytes", "evidence"}
    if set(row) != keys or row.get("format") != SIZE_REVIEW_FORMAT:
        raise ValueError(f"{where}: expected exact {SIZE_REVIEW_FORMAT} fields")
    if _require_text(row["program_id"], f"{where}: program_id") != program_id:
        raise ValueError(f"{where}: program_id does not match {program_id!r}")
    if row["program_sha256"] != program_sha256:
        raise ValueError(f"{where}: program_sha256 does not match the pinned program")
    type_id = _require_text(row["type_id"], f"{where}: type_id")
    size = _require_int(row["exact_size_bytes"], f"{where}: exact_size_bytes", minimum=1)
    evidence = row["evidence"]
    evidence_keys = {"source_format", "source_sha256", "record_key", "source_pointer", "evidence_class"}
    if not isinstance(evidence, dict) or set(evidence) != evidence_keys:
        raise ValueError(f"{where}: evidence must have exact source fields")
    source_format = _require_text(evidence["source_format"], f"{where}: evidence.source_format")
    source_sha256 = evidence["source_sha256"]
    if not isinstance(source_sha256, str) or not SHA256_RE.fullmatch(source_sha256):
        raise ValueError(f"{where}: evidence.source_sha256 must be lowercase SHA-256")
    record_key = _require_text(evidence["record_key"], f"{where}: evidence.record_key")
    source_pointer = _require_text(evidence["source_pointer"], f"{where}: evidence.source_pointer")
    evidence_class = evidence["evidence_class"]
    if not isinstance(evidence_class, str) or evidence_class not in {
        "exact_static", "runtime_native", "derived_structural", "human_review", "interventional_probe",
    }:
        raise ValueError(f"{where}: unsupported evidence_class")
    return type_id, size, {
        "source_format": source_format,
        "source_sha256": source_sha256,
        "record_key": record_key,
        "source_pointer": source_pointer,
        "evidence_class": evidence_class,
    }


def _read_parameter_loads(
    paths: list[Path], *, max_rows: int,
) -> Iterator[tuple[Path, str, int, dict[str, str]]]:
    rows_seen = 0
    for path in paths:
        digest = _sha256(path)
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle, delimiter="\t")
            if tuple(reader.fieldnames or ()) != LOAD_COLUMNS:
                raise ValueError(f"{path}: unexpected GhidraParameterLoadField/1 TSV header")
            for line_no, row in enumerate(reader, 2):
                if row is None:
                    continue
                if None in row:
                    raise ValueError(f"{path}:{line_no}: malformed GhidraParameterLoadField/1 TSV row")
                if all(value is None or not value.strip() for value in row.values()):
                    continue
                rows_seen += 1
                if rows_seen > max_rows:
                    raise ValueError(f"combined parameter-load row budget exceeded: {max_rows}")
                if set(row) != set(LOAD_COLUMNS) or any(not isinstance(value, str) for value in row.values()):
                    raise ValueError(f"{path}:{line_no}: malformed GhidraParameterLoadField/1 TSV row")
                yield path, digest, line_no, row


def build_type_layout_hypotheses(
    memory_store_paths: list[Path],
    member_map_paths: list[Path],
    *,
    parameter_load_paths: list[Path] | None = None,
    size_review_paths: list[Path] | None = None,
    program_id: str,
    program_sha256: str,
    language_id: str,
    pointer_width_bytes: int,
    addressable_unit_bytes: int,
    endianness: str,
    max_rows: int = DEFAULT_MAX_ROWS,
) -> list[dict[str, Any]]:
    """Join accesses to explicit members and attach only reviewer-supplied exact sizes."""
    parameter_load_paths = parameter_load_paths or []
    size_review_paths = size_review_paths or []
    if not member_map_paths or (not memory_store_paths and not parameter_load_paths):
        raise ValueError("provide a member map and at least one memory-store or parameter-load input")
    if not isinstance(program_sha256, str) or not SHA256_RE.fullmatch(program_sha256):
        raise ValueError("program_sha256 must be 64 lowercase hexadecimal characters")
    _require_int(max_rows, "max_rows", minimum=1)
    architecture = {
        "language_id": _require_text(language_id, "language_id"),
        "pointer_width_bytes": _require_int(pointer_width_bytes, "pointer_width_bytes", minimum=1),
        "addressable_unit_bytes": _require_int(addressable_unit_bytes, "addressable_unit_bytes", minimum=1),
        "endianness": endianness,
    }
    if endianness not in ("little", "big"):
        raise ValueError("endianness must be little or big")
    _require_text(program_id, "program_id")

    memberships: dict[tuple[str, int], tuple[dict[str, Any], dict[str, str]]] = {}
    member_rows = 0
    for path in member_map_paths:
        digest = _sha256(path)
        for line_no, row in _read_jsonl(path, max_rows=max_rows):
            member_rows += 1
            if member_rows > max_rows:
                raise ValueError(f"combined member-map row budget exceeded: {max_rows}")
            where = f"{path}:{line_no}"
            key = _validate_member(row, where, program_id=program_id, program_sha256=program_sha256)
            join_key = (key[0], key[1])
            if join_key in memberships:
                raise ValueError(f"{where}: duplicate member-map join key {join_key!r}")
            map_ref = _evidence(
                source_format=MEMBER_FORMAT,
                source_sha256=digest,
                record_key=f"function={key[0]};root_parameter_index={key[1]};type_id={key[2]}",
                evidence_class="human_review",
            )
            memberships[join_key] = (row, map_ref)

    size_reviews: dict[str, list[tuple[int, list[dict[str, str]]]]] = defaultdict(list)
    review_rows = 0
    for path in size_review_paths:
        digest = _sha256(path)
        for line_no, row in _read_jsonl(path, max_rows=max_rows):
            review_rows += 1
            if review_rows > max_rows:
                raise ValueError(f"combined size-review row budget exceeded: {max_rows}")
            where = f"{path}:{line_no}"
            type_id, size_bytes, evidence = _validate_size_review(
                row, where, program_id=program_id, program_sha256=program_sha256,
            )
            review_ref = _evidence(
                source_format=SIZE_REVIEW_FORMAT,
                source_sha256=digest,
                record_key=f"type_id={type_id};exact_size_bytes={size_bytes}",
                evidence_class="human_review",
            )
            size_reviews[type_id].append((size_bytes, [evidence, review_ref]))

    grouped: dict[str, dict[int, dict[tuple[str, int | None], list[dict[str, str]]]]] = defaultdict(
        lambda: defaultdict(lambda: defaultdict(list))
    )
    size_evidence: dict[str, dict[int, list[dict[str, str]]]] = defaultdict(lambda: defaultdict(list))
    seen_stores: set[tuple[str, str, int]] = set()
    store_rows = 0
    for path in memory_store_paths:
        digest = _sha256(path)
        for line_no, row in _read_jsonl(path, max_rows=max_rows):
            store_rows += 1
            if store_rows > max_rows:
                raise ValueError(f"combined memory-store row budget exceeded: {max_rows}")
            where = f"{path}:{line_no}"
            _validate_store(row, where, program_id=program_id)
            site_key = (row["function_entry"], row["address"], row["time"])
            if site_key in seen_stores:
                raise ValueError(f"{where}: duplicate memory-store site {site_key!r}")
            seen_stores.add(site_key)
            if row["location_status"] != "parameter_rooted_constant_offset":
                continue
            if row["offset_bytes"] < 0:
                continue
            membership = memberships.get((row["function_entry"], row["root_parameter_index"]))
            if membership is None:
                continue
            member_row, member_ref = membership
            type_id = member_row["type_id"]
            store_ref = _evidence(
                source_format=STORE_FORMAT,
                source_sha256=digest,
                record_key=(
                    f"function={row['function_entry']};address={row['address']};"
                    f"time={row['time']};output="
                ),
                evidence_class="exact_static",
            )
            offset = row["offset_bytes"]
            width = row["memory_width_bytes"]
            access_refs = [store_ref, member_ref]
            grouped[type_id][offset][("write", width)].extend(access_refs)
            if width is not None:
                extent = offset + width
                size_evidence[type_id][extent].extend(access_refs)

    seen_loads: set[tuple[str, str, str]] = set()
    for path, digest, line_no, row in _read_parameter_loads(parameter_load_paths or [], max_rows=max_rows):
        where = f"{path}:{line_no}"
        if row["format"] != LOAD_FORMAT or row["status"] != "parameter_field_load":
            raise ValueError(f"{where}: expected {LOAD_FORMAT}")
        function_entry = _require_text(row["function_entry"], f"{where}: function_entry")
        _require_text(row["function_name"], f"{where}: function_name")
        address = _require_text(row["load_address"], f"{where}: load_address")
        load_time = row["load_time"]
        if load_time != "-":
            _parse_decimal(load_time, f"{where}: load_time")
        root_index = _parse_decimal(row["base_parameter_index"], f"{where}: base_parameter_index")
        offset_text = row["field_offset"]
        if not re.fullmatch(r"-?0x[0-9a-f]+", offset_text):
            raise ValueError(f"{where}: invalid field_offset {offset_text!r}")
        offset = int(offset_text, 16)
        _require_text(row["address_pattern"], f"{where}: address_pattern")
        width = _parse_decimal(row["value_size"], f"{where}: value_size", minimum=1)
        value_token = _require_text(row["value_token"], f"{where}: value_token")
        site_key = (function_entry, address, load_time)
        if site_key in seen_loads:
            raise ValueError(f"{where}: duplicate parameter-load site {site_key!r}")
        seen_loads.add(site_key)
        if offset < 0:
            continue
        membership = memberships.get((function_entry, root_index))
        if membership is None:
            continue
        member_row, member_ref = membership
        type_id = member_row["type_id"]
        load_ref = _evidence(
            source_format=LOAD_FORMAT,
            source_sha256=digest,
            record_key=(
                f"function={function_entry};address={address};time={load_time};output={value_token}"
            ),
            evidence_class="exact_static",
        )
        access_refs = [load_ref, member_ref]
        grouped[type_id][offset][("read", width)].extend(access_refs)
        size_evidence[type_id][offset + width].extend(access_refs)

    results: list[dict[str, Any]] = []
    for type_id in sorted(grouped):
        type_fields: list[dict[str, Any]] = []
        offsets = grouped[type_id]
        for offset in sorted(offsets):
            accesses = []
            for access_key, refs in sorted(
                offsets[offset].items(),
                key=lambda item: (item[0][0], item[0][1] is None, item[0][1] or 0),
            ):
                accesses.append({
                    "kind": access_key[0],
                    "width_bytes": access_key[1],
                    "evidence": _sort_evidence(refs),
                })
            type_fields.append({
                "offset_bytes": offset,
                "status": "candidate",
                "accesses": accesses,
                "type_candidates": [],
                "conflicts": [],
            })
        max_extent = max(size_evidence[type_id], default=None)
        bound_refs = _sort_evidence(size_evidence[type_id][max_extent]) if max_extent is not None else []
        reviews = size_reviews.pop(type_id, [])
        reviewed_sizes = {size for size, _ in reviews}
        review_refs = _sort_evidence(
            evidence for _, review_evidence in reviews for evidence in review_evidence
        )
        conflicts: list[dict[str, Any]] = []
        exact_size = next(iter(reviewed_sizes)) if len(reviewed_sizes) == 1 else None
        if len(reviewed_sizes) > 1:
            conflicts.append({"reason": "evidence_conflict", "evidence": review_refs})
        if max_extent is not None and any(size < max_extent for size in reviewed_sizes):
            conflicts.append({
                "reason": "size_bound_conflict",
                "evidence": _sort_evidence([*bound_refs, *review_refs]),
            })
        size_status = "conflicted" if conflicts else "candidate"
        results.append({
            "format": OUTPUT_FORMAT,
            "program_id": program_id,
            "program_sha256": program_sha256,
            "type_id": type_id,
            "architecture": architecture,
            "status": size_status,
            "object_size": {
                "minimum_observed_bytes": max_extent,
                "exact_size_bytes": exact_size,
                "evidence": _sort_evidence([*bound_refs, *review_refs]),
            },
            "fields": type_fields,
            "vtable_anchors": [],
            "relationships": [],
            "conflicts": conflicts,
        })
    if size_reviews:
        raise ValueError(f"size reviews do not match a mapped type: {sorted(size_reviews)}")
    if not results:
        raise ValueError("no non-negative parameter-rooted stores matched the member map")
    return results


def _write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", newline="", dir=path.parent,
            prefix=f".{path.name}.", suffix=".tmp", delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            for row in rows:
                handle.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
        os.replace(temporary_path, path)
    except Exception:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--memory-store-jsonl", action="append", type=Path, default=[])
    parser.add_argument("--parameter-loads-tsv", action="append", type=Path, default=[])
    parser.add_argument("--member-map-jsonl", action="append", type=Path, required=True)
    parser.add_argument("--size-review-jsonl", action="append", type=Path, default=[])
    parser.add_argument("--program-id", required=True)
    parser.add_argument("--program-sha256", required=True)
    parser.add_argument("--language-id", required=True)
    parser.add_argument("--pointer-width-bytes", type=int, required=True)
    parser.add_argument("--addressable-unit-bytes", type=int, default=1)
    parser.add_argument("--endianness", choices=("little", "big"), required=True)
    parser.add_argument("--max-rows", type=int, default=DEFAULT_MAX_ROWS)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)

    if args.output != Path("-"):
        output_resolved = args.output.resolve()
        inputs = (
            args.memory_store_jsonl + args.parameter_loads_tsv
            + args.member_map_jsonl + args.size_review_jsonl
        )
        if any(path.resolve() == output_resolved for path in inputs):
            parser.error("output must not overwrite an input artifact")
    try:
        rows = build_type_layout_hypotheses(
            args.memory_store_jsonl,
            args.member_map_jsonl,
            parameter_load_paths=args.parameter_loads_tsv,
            size_review_paths=args.size_review_jsonl,
            program_id=args.program_id,
            program_sha256=args.program_sha256,
            language_id=args.language_id,
            pointer_width_bytes=args.pointer_width_bytes,
            addressable_unit_bytes=args.addressable_unit_bytes,
            endianness=args.endianness,
            max_rows=args.max_rows,
        )
        if args.output == Path("-"):
            for row in rows:
                sys.stdout.write(json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n")
        else:
            _write_jsonl(args.output, rows)
    except (OSError, ValueError) as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
