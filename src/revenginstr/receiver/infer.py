#!/usr/bin/env python3
"""Infer receiver class/vtable identity from conservative type evidence.

The algorithm is project-neutral. The catalog is data supplied by a consumer and
needs only `class_name` and `receiver_vtable_id` fields. No dispatch slot or
virtual target is inferred here and the output never affects routing by itself.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

FORMAT = "REVENGINSTR.ReceiverInference/1"
FAILURE_FORMAT = "REVENGINSTR.ReceiverFailureReason/1"
ASSESSMENT_FORMAT = "REVENGINSTR.ReceiverCandidateAssessment/1"

PRIMARY_FAILURE_REASON_CODES = frozenset({
    "ambiguous_phi",
    "ambiguous_receiver_vtable",
    "caller_argument_propagation_gap",
    "factory_return_gap",
    "field_load_store_propagation_gap",
    "insufficient_receiver_type_evidence",
    "linker_veneer_artifact",
    "missing_root_provenance",
    "missing_vtable_catalog_entry",
    "mixed_receiver_candidates",
    "nested_container_object_gap",
    "non_virtual_call_indirect",
    "pcode_decompiler_limitation",
    "receiver_not_single_pointer",
    "singleton_default_instance_gap",
    "slot_ambiguity",
    "unsupported_pattern",
})


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_no, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            row = json.loads(raw)
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_no}: expected object")
            rows.append(row)
    return rows


def read_tsv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle, delimiter="\t"))


def parse_int_cell(value: Any, default: int = 0) -> int:
    if value in (None, "", "-"):
        return default
    try:
        return int(str(value), 0)
    except ValueError as error:
        raise ValueError(f"invalid integer cell: {value!r}") from error


def parse_json_string_list(value: Any, where: str) -> list[str]:
    if value in (None, "", "-"):
        return []
    if not isinstance(value, str):
        raise ValueError(f"{where}: expected JSON string list")
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as error:
        raise ValueError(f"{where}: invalid JSON string list") from error
    if not isinstance(parsed, list) or not all(isinstance(item, str) for item in parsed):
        raise ValueError(f"{where}: expected JSON array of strings")
    return parsed


def clean_type_name(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or text == "-" or text == "void":
        return None
    text = re.sub(r"^(?:class|struct)\s+", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text or None


def terminal_class_name(name: str) -> str:
    return name.rsplit("::", 1)[-1]


def source_entry(source_id: str) -> str:
    return source_id.split(":", 1)[1] if ":" in source_id else source_id


def build_catalog(rows: list[dict[str, Any]]) -> tuple[dict[str, set[str]], dict[str, set[str]]]:
    class_vtables: dict[str, set[str]] = defaultdict(set)
    for line_no, row in enumerate(rows, 1):
        class_name = row.get("class_name")
        vtable_id = row.get("receiver_vtable_id")
        if not isinstance(class_name, str) or not class_name:
            raise ValueError(f"catalog row {line_no}: missing class_name")
        if not isinstance(vtable_id, str) or not vtable_id:
            raise ValueError(f"catalog row {line_no}: missing receiver_vtable_id")
        class_vtables[class_name].add(vtable_id)
    terminal_to_classes: dict[str, set[str]] = defaultdict(set)
    for class_name in class_vtables:
        terminal_to_classes[terminal_class_name(class_name)].add(class_name)
    return class_vtables, terminal_to_classes


def resolve_type(raw: Any, class_vtables: dict[str, set[str]],
                 terminal_to_classes: dict[str, set[str]]) -> list[tuple[str, str]]:
    cleaned = clean_type_name(raw)
    if cleaned is None:
        return []
    if cleaned in class_vtables:
        return [(cleaned, "exact_catalog_class_name")]
    terminal = terminal_class_name(cleaned)
    classes = terminal_to_classes.get(terminal, set())
    if len(classes) == 1:
        return [(next(iter(classes)), "unique_terminal_class_name")]
    return []


def candidates(typed_sources: list[tuple[Any, str]], class_vtables: dict[str, set[str]],
               terminal_to_classes: dict[str, set[str]]) -> list[tuple[str, str, str]]:
    result: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    for raw, source_kind in typed_sources:
        cleaned = clean_type_name(raw)
        if cleaned is None or (cleaned, source_kind) in seen:
            continue
        seen.add((cleaned, source_kind))
        for class_name, match_kind in resolve_type(cleaned, class_vtables, terminal_to_classes):
            result.append((class_name, match_kind, source_kind))
    return result


def build_compatibility_groups(catalog_rows: list[dict[str, Any]]) -> dict[str, str]:
    """Read optional consumer-declared compatibility groups from the catalog."""
    groups_by_class: dict[str, set[str]] = defaultdict(set)
    for row in catalog_rows:
        class_name = row.get("class_name")
        group_id = row.get("receiver_compatibility_group_id")
        if isinstance(class_name, str) and class_name and isinstance(group_id, str):
            if group_id and group_id != "-":
                groups_by_class[class_name].add(group_id)
    return {
        class_name: next(iter(group_ids))
        for class_name, group_ids in groups_by_class.items()
        if len(group_ids) == 1
    }


def candidate_assessment(
    typed_sources: list[tuple[Any, str]],
    class_vtables: dict[str, set[str]],
    terminal_to_classes: dict[str, set[str]],
    compatibility_groups: dict[str, str],
) -> tuple[str, list[str], int, str | None]:
    possible_classes: set[str] = set()
    unknown_types: set[str] = set()
    for raw, _source_kind in typed_sources:
        cleaned = clean_type_name(raw)
        if cleaned is None:
            continue
        resolved = resolve_type(cleaned, class_vtables, terminal_to_classes)
        if resolved:
            possible_classes.update(name for name, _match in resolved)
        elif cleaned not in class_vtables:
            terminal_matches = terminal_to_classes.get(terminal_class_name(cleaned), set())
            if len(terminal_matches) > 1:
                possible_classes.update(terminal_matches)
            else:
                unknown_types.add(cleaned)

    candidates = sorted(possible_classes)
    unknown_count = len(unknown_types)
    group_ids = {compatibility_groups.get(name) for name in candidates}
    compatible = (
        len(candidates) > 1
        and None not in group_ids
        and len(group_ids) == 1
    )
    common_group = next(iter(group_ids)) if compatible else None

    if not candidates:
        status = "no_known_candidates"
    elif len(candidates) == 1:
        status = "partially_unknown_candidates" if unknown_count else "same_type_convergence"
    elif compatible and unknown_count:
        status = "partially_unknown_candidates"
    elif compatible:
        status = "compatible_subtype_candidates"
    else:
        status = "mixed_candidates"
    return status, candidates, unknown_count, common_group


def primary_failure_reason(status: str, typed_sources: list[tuple[Any, str]],
                           class_vtables: dict[str, set[str]],
                           terminal_to_classes: dict[str, set[str]]) -> str | None:
    if status == "resolved_unique_vtable":
        return None
    if status == "receiver_not_single_pointer":
        return "receiver_not_single_pointer"
    if status == "ambiguous_receiver_class":
        return "mixed_receiver_candidates"
    if status == "ambiguous_class_vtable":
        return "ambiguous_receiver_vtable"
    if status != "unresolved_receiver_class":
        raise AssertionError(f"unmapped receiver inference status: {status}")

    type_names = [clean_type_name(raw) for raw, _source_kind in typed_sources]
    type_names = [name for name in type_names if name is not None]
    if any(
        name not in class_vtables
        and len(terminal_to_classes.get(terminal_class_name(name), set())) > 1
        for name in type_names
    ):
        return "mixed_receiver_candidates"
    return "missing_vtable_catalog_entry" if type_names else "insufficient_receiver_type_evidence"


def _infer(
    receiver_rows: list[dict[str, str]],
    catalog_rows: list[dict[str, Any]],
    *,
    include_failure_reasons: bool,
    include_candidate_assessments: bool = False,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    class_vtables, terminal_to_classes = build_catalog(catalog_rows)
    compatibility_groups = (
        build_compatibility_groups(catalog_rows) if include_candidate_assessments else {}
    )
    output: list[dict[str, Any]] = []
    failure_rows: list[dict[str, Any]] = []
    assessment_rows: list[dict[str, Any]] = []
    seen_keys: set[tuple[str, int]] = set()

    for line_no, receiver in enumerate(receiver_rows, 2):
        source_id = receiver.get("source_id")
        try:
            call_index = int(receiver.get("call_index", "-1"))
        except ValueError as error:
            raise ValueError(f"receiver row {line_no}: invalid call_index") from error
        if not source_id or call_index < 0:
            raise ValueError(f"receiver row {line_no}: invalid receiver key")
        key = (source_id, call_index)
        if key in seen_keys:
            raise ValueError(f"duplicate receiver row: {source_id}#{call_index}")
        seen_keys.add(key)

        pointer_depth = parse_int_cell(receiver.get("receiver_pointer_depth"))
        flow_names = parse_json_string_list(
            receiver.get("flow_single_pointer_pointee_names_json"), f"receiver row {line_no}: flow names"
        )
        flow_displays = parse_json_string_list(
            receiver.get("flow_single_pointer_pointee_displays_json"), f"receiver row {line_no}: flow displays"
        )

        base: dict[str, Any] = {
            "format": FORMAT,
            "source_id": source_id,
            "source_entry": source_entry(source_id),
            "call_index": call_index,
            "call_address": receiver.get("call_address"),
            "dispatch_slot_offset": None,
            "slot_evidence_present": False,
            "resolution_scope": "receiver_identity_only_no_dispatch_slot",
            "receiver_type_evidence_present": True,
            "receiver_type_format": receiver.get("format"),
            "receiver_type_name": receiver.get("receiver_type_name"),
            "receiver_type_display": receiver.get("receiver_type_display"),
            "receiver_pointer_depth": pointer_depth,
            "pointee_type_name": receiver.get("pointee_type_name"),
            "pointee_type_display": receiver.get("pointee_type_display"),
            "receiver_storage_kind": receiver.get("receiver_storage_kind"),
            "flow_type_node_count": parse_int_cell(receiver.get("flow_type_node_count")),
            "flow_single_pointer_pointee_names": flow_names,
            "flow_single_pointer_pointee_displays": flow_displays,
            "class_name": None,
            "class_match_kind": None,
            "class_evidence_source": None,
            "candidate_receiver_class_names": [],
            "candidate_receiver_vtable_ids": [],
            "receiver_vtable_id": None,
            "affects_routing": False,
            "target_transfer_scope": "disabled_without_dispatch_slot",
            "cross_vtable_transfer_allowed": False,
            "cross_class_transfer_allowed": False,
        }

        typed_sources: list[tuple[Any, str]] = []
        if pointer_depth == 1:
            typed_sources.extend([
                (receiver.get("pointee_type_display"), "direct_receiver_type"),
                (receiver.get("pointee_type_name"), "direct_receiver_type"),
            ])
        typed_sources.extend((value, "transparent_type_flow") for value in flow_displays)
        typed_sources.extend((value, "transparent_type_flow") for value in flow_names)

        found = candidates(typed_sources, class_vtables, terminal_to_classes)
        class_names = sorted({name for name, _match, _source in found})
        base["candidate_receiver_class_names"] = class_names

        if not class_names:
            status = (
                "receiver_not_single_pointer"
                if pointer_depth != 1 and not flow_names and not flow_displays
                else "unresolved_receiver_class"
            )
        elif len(class_names) > 1:
            status = "ambiguous_receiver_class"
        else:
            class_name = class_names[0]
            exact = [item for item in found if item[0] == class_name and item[1] == "exact_catalog_class_name"]
            chosen = exact[0] if exact else next(item for item in found if item[0] == class_name)
            _name, match_kind, source_kind = chosen
            if source_kind == "transparent_type_flow":
                match_kind = "transparent_flow_" + match_kind
            vtables = sorted(class_vtables[class_name])
            base["class_name"] = class_name
            base["class_match_kind"] = match_kind
            base["class_evidence_source"] = source_kind
            base["candidate_receiver_vtable_ids"] = vtables
            if len(vtables) != 1:
                status = "ambiguous_class_vtable"
            else:
                status = "resolved_unique_vtable"
                base["receiver_vtable_id"] = vtables[0]
        base["status"] = status
        output.append(base)

        if include_candidate_assessments:
            assessment_status, assessment_candidates, unknown_count, group_id = candidate_assessment(
                typed_sources, class_vtables, terminal_to_classes, compatibility_groups
            )
            assessment_rows.append({
                "format": ASSESSMENT_FORMAT,
                "source_id": source_id,
                "source_entry": source_entry(source_id),
                "call_index": call_index,
                "call_address": receiver.get("call_address"),
                "status": assessment_status,
                "candidate_receiver_class_names": assessment_candidates,
                "unknown_type_candidate_count": unknown_count,
                "compatibility_group_id": group_id,
            })

        if not include_failure_reasons:
            continue
        reason = primary_failure_reason(status, typed_sources, class_vtables, terminal_to_classes)
        if reason is not None:
            if reason not in PRIMARY_FAILURE_REASON_CODES:
                raise AssertionError(f"unregistered receiver failure reason: {reason}")
            failure_rows.append({
                "format": FAILURE_FORMAT,
                "source_id": source_id,
                "source_entry": source_entry(source_id),
                "call_index": call_index,
                "call_address": receiver.get("call_address"),
                "status": status,
                "primary_failure_reason": reason,
            })
    return output, failure_rows, assessment_rows


def infer_with_failure_reasons(
    receiver_rows: list[dict[str, str]], catalog_rows: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows, failures, _assessments = _infer(
        receiver_rows, catalog_rows, include_failure_reasons=True
    )
    return rows, failures


def infer_with_candidate_assessments(
    receiver_rows: list[dict[str, str]], catalog_rows: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    rows, _failures, assessments = _infer(
        receiver_rows,
        catalog_rows,
        include_failure_reasons=False,
        include_candidate_assessments=True,
    )
    return rows, assessments


def infer(receiver_rows: list[dict[str, str]], catalog_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return the unchanged ReceiverInference/1 rows."""
    return _infer(receiver_rows, catalog_rows, include_failure_reasons=False)[0]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("receiver_types_tsv", type=Path)
    parser.add_argument("catalog", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--failure-reasons-output", type=Path)
    parser.add_argument("--candidate-assessments-output", type=Path)
    args = parser.parse_args(argv)

    receiver_rows = read_tsv(args.receiver_types_tsv)
    catalog_rows = read_jsonl(args.catalog)
    include_assessments = args.candidate_assessments_output is not None
    if args.failure_reasons_output is None and not include_assessments:
        rows = infer(receiver_rows, catalog_rows)
        failure_rows = []
        assessment_rows = []
    else:
        rows, failure_rows, assessment_rows = _infer(
            receiver_rows,
            catalog_rows,
            include_failure_reasons=args.failure_reasons_output is not None,
            include_candidate_assessments=include_assessments,
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    counts: Counter[str] = Counter(row["status"] for row in rows)
    resolved_functions = {row["source_id"] for row in rows if row["status"] == "resolved_unique_vtable"}
    with args.output.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    if args.failure_reasons_output is not None:
        args.failure_reasons_output.parent.mkdir(parents=True, exist_ok=True)
        with args.failure_reasons_output.open("w", encoding="utf-8") as handle:
            for row in failure_rows:
                handle.write(json.dumps(row, sort_keys=True) + "\n")
    if args.candidate_assessments_output is not None:
        args.candidate_assessments_output.parent.mkdir(parents=True, exist_ok=True)
        with args.candidate_assessments_output.open("w", encoding="utf-8") as handle:
            for row in assessment_rows:
                handle.write(json.dumps(row, sort_keys=True) + "\n")
    print("format:", FORMAT)
    print("calls considered:", len(rows))
    print("functions with resolved receiver vtable:", len(resolved_functions))
    print("statuses:", dict(sorted(counts.items())))
    if args.failure_reasons_output is not None:
        reason_counts = Counter(row["primary_failure_reason"] for row in failure_rows)
        print("primary failure reasons:", dict(sorted(reason_counts.items())))
    if args.candidate_assessments_output is not None:
        assessment_counts = Counter(row["status"] for row in assessment_rows)
        print("candidate assessments:", dict(sorted(assessment_counts.items())))
    print("dispatch slots inferred: 0")
    print("affects routing: no")
    print("output:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
