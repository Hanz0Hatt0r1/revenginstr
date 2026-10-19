"""Evaluate type-layout hypotheses against independently adjudicated gold."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .type_layout_builder import OUTPUT_FORMAT, TYPE_KINDS

FORMAT = "REVENGINSTR.TypeLayoutEvaluation/1"
GOLD_FORMAT = "REVENGINSTR.TypeLayoutGold/1"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    row = {}
    for key, value in pairs:
        if key in row:
            raise ValueError(f"duplicate JSON key {key!r}")
        row[key] = value
    return row


def _reject_constant(value: str) -> None:
    raise ValueError(f"non-JSON numeric constant {value}")


def _read_jsonl(path: Path) -> tuple[list[dict[str, Any]], str]:
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"{path}: input is not valid UTF-8") from error
    rows = []
    for line_no, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        try:
            row = json.loads(
                line, object_pairs_hook=_unique_object, parse_constant=_reject_constant,
            )
        except (ValueError, UnicodeDecodeError) as error:
            raise ValueError(f"{path}:{line_no}: invalid JSON: {error}") from error
        if not isinstance(row, dict):
            raise ValueError(f"{path}:{line_no}: expected a JSON object")
        rows.append(row)
    return rows, digest


def _text(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{where}: expected a non-empty string")
    return value


def _offset(value: Any, where: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{where}: expected a non-negative integer")
    return value


def _validate_evidence_refs(value: Any, where: str, forbidden_hashes: set[str]) -> None:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{where}: evidence_refs must be a non-empty array")
    for index, ref in enumerate(value, 1):
        ref_where = f"{where}: evidence_ref {index}"
        if not isinstance(ref, dict) or set(ref) != {"artifact_sha256", "record_index", "source_format"}:
            raise ValueError(f"{ref_where}: invalid fields")
        digest = ref["artifact_sha256"]
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise ValueError(f"{ref_where}: invalid artifact_sha256")
        if digest in forbidden_hashes:
            raise ValueError(f"{ref_where}: gold cannot cite evaluated or gold output")
        if type(ref["record_index"]) is not int or ref["record_index"] < 1:
            raise ValueError(f"{ref_where}: invalid record_index")
        _text(ref["source_format"], ref_where)


def _validate_gold(
    row: Any, index: int, *, gold_sha256: str, prediction_sha256: str,
) -> tuple[tuple[str, str, str], dict[str, Any]]:
    where = f"gold record {index}"
    required = {
        "format", "dataset_id", "split_id", "program_id", "program_sha256", "type_id",
        "audited_field_offsets", "fields", "adjudication_status",
    }
    if not isinstance(row, dict) or set(row) != required or row.get("format") != GOLD_FORMAT:
        raise ValueError(f"{where}: unsupported format or fields")
    _text(row["dataset_id"], where)
    _text(row["split_id"], where)
    program = _text(row["program_id"], where)
    type_id = _text(row["type_id"], where)
    if not isinstance(row["program_sha256"], str) or not _SHA256.fullmatch(row["program_sha256"]):
        raise ValueError(f"{where}: invalid program_sha256")
    if row["adjudication_status"] != "adjudicated":
        raise ValueError(f"{where}: gold layout is not adjudicated")
    audited_rows = row["audited_field_offsets"]
    if not isinstance(audited_rows, list) or not audited_rows:
        raise ValueError(f"{where}: audited_field_offsets must be non-empty")
    audited = {_offset(value, where) for value in audited_rows}
    if len(audited) != len(audited_rows):
        raise ValueError(f"{where}: duplicate audited field offset")
    if not isinstance(row["fields"], list):
        raise ValueError(f"{where}: fields must be an array")
    seen_fields = set()
    for field_index, field in enumerate(row["fields"], 1):
        field_where = f"{where}: field {field_index}"
        if not isinstance(field, dict) or set(field) - {
            "offset_bytes", "compatible_types", "evidence_refs",
        } or not {"offset_bytes", "evidence_refs"} <= set(field):
            raise ValueError(f"{field_where}: invalid fields")
        offset = _offset(field["offset_bytes"], field_where)
        if offset not in audited:
            raise ValueError(f"{field_where}: positive field is outside audited_field_offsets")
        if offset in seen_fields:
            raise ValueError(f"{field_where}: duplicate field offset")
        seen_fields.add(offset)
        _validate_evidence_refs(
            field["evidence_refs"], field_where, {gold_sha256, prediction_sha256},
        )
        if "compatible_types" in field:
            choices = field["compatible_types"]
            if not isinstance(choices, list) or not choices:
                raise ValueError(f"{field_where}: compatible_types must be a non-empty array")
            for choice in choices:
                if not isinstance(choice, dict) or set(choice) - {"kind", "width_bytes", "target_type_id"}:
                    raise ValueError(f"{field_where}: invalid compatible type")
                if not {"kind", "width_bytes"} <= set(choice) or choice["kind"] not in TYPE_KINDS:
                    raise ValueError(f"{field_where}: invalid compatible type kind/width")
                width = choice["width_bytes"]
                if width is not None and (type(width) is not int or width < 1):
                    raise ValueError(f"{field_where}: invalid compatible type width")
                if "target_type_id" in choice:
                    _text(choice["target_type_id"], field_where)
                if choice.get("target_type_id") is not None and choice["kind"] != "data_pointer":
                    raise ValueError(f"{field_where}: target_type_id requires data_pointer")
    return (program, row["program_sha256"], type_id), row


def _type_matches(candidate: dict[str, Any], compatible: dict[str, Any]) -> bool:
    return (
        candidate.get("kind") == compatible["kind"]
        and (
            compatible["width_bytes"] is None
            or candidate.get("width_bytes") == compatible["width_bytes"]
        )
        and (
            "target_type_id" not in compatible
            or candidate.get("target_type_id") == compatible["target_type_id"]
        )
    )


def _ratio(numerator: int, denominator: int) -> float | None:
    return numerator / denominator if denominator else None


def _validate_prediction_field(field: Any, where: str) -> int:
    if not isinstance(field, dict) or type(field.get("offset_bytes")) is not int or field["offset_bytes"] < 0:
        raise ValueError(f"{where}: invalid field offset")
    if field.get("status") not in {"candidate", "review", "conflicted"}:
        raise ValueError(f"{where}: invalid field status")
    candidates = field.get("type_candidates")
    if not isinstance(candidates, list):
        raise ValueError(f"{where}: type_candidates must be an array")
    for type_index, candidate in enumerate(candidates, 1):
        type_where = f"{where}: type candidate {type_index}"
        if not isinstance(candidate, dict) or candidate.get("kind") not in TYPE_KINDS:
            raise ValueError(f"{type_where}: invalid type kind")
        width = candidate.get("width_bytes")
        if width is not None and (type(width) is not int or width < 1):
            raise ValueError(f"{type_where}: invalid type width")
        if "target_type_id" in candidate:
            _text(candidate["target_type_id"], type_where)
            if candidate["kind"] != "data_pointer":
                raise ValueError(f"{type_where}: target_type_id requires data_pointer")
    return field["offset_bytes"]


def evaluate_type_layouts(predictions_path: Path, gold_path: Path) -> dict[str, Any]:
    """Score fields only inside explicit gold coverage; unreviewed offsets are unknown."""
    predictions, predictions_sha256 = _read_jsonl(predictions_path)
    gold_rows, gold_sha256 = _read_jsonl(gold_path)
    predicted_by_key: dict[tuple[str, str, str], dict[str, Any]] = {}
    for index, row in enumerate(predictions, 1):
        if row.get("format") != OUTPUT_FORMAT:
            raise ValueError(f"prediction record {index}: expected {OUTPUT_FORMAT}")
        key = (row.get("program_id"), row.get("program_sha256"), row.get("type_id"))
        if (
            not isinstance(key[0], str) or not key[0]
            or not isinstance(key[1], str) or not _SHA256.fullmatch(key[1])
            or not isinstance(key[2], str) or not key[2]
        ):
            raise ValueError(f"prediction record {index}: invalid layout identity")
        if key in predicted_by_key:
            raise ValueError(f"prediction record {index}: duplicate layout identity")
        if not isinstance(row.get("fields"), list) or row.get("status") not in {"candidate", "review", "conflicted"}:
            raise ValueError(f"prediction record {index}: invalid layout fields/status")
        predicted_by_key[key] = row
    if not gold_rows:
        raise ValueError("gold input is empty")

    metadata: tuple[str, str] | None = None
    seen_gold: set[tuple[str, str, str]] = set()
    gold_field_count = candidate_field_count = true_positive_count = 0
    unscored_candidate_count = 0
    type_label_count = reviewed_type_count = compatible_type_count = 0
    reviewed_field_count = accepted_review_count = 0
    conflicted_layout_count = predicted_layout_count = evaluated_layout_count = 0
    conflicted_field_count = output_field_count = 0

    for index, raw in enumerate(gold_rows, 1):
        key, row = _validate_gold(
            raw, index, gold_sha256=gold_sha256, prediction_sha256=predictions_sha256,
        )
        if key in seen_gold:
            raise ValueError(f"gold record {index}: duplicate layout identity")
        seen_gold.add(key)
        current_metadata = (row["dataset_id"], row["split_id"])
        if metadata is None:
            metadata = current_metadata
        elif metadata != current_metadata:
            raise ValueError(f"gold record {index}: mixed dataset or split identity")

        prediction = predicted_by_key.get(key)
        evaluated_layout_count += 1
        if prediction is None:
            predicted_fields = []
        else:
            predicted_layout_count += 1
            predicted_fields = prediction["fields"]
            conflicted_layout_count += prediction["status"] == "conflicted"
        audited = set(row["audited_field_offsets"])
        gold_fields = {field["offset_bytes"]: field for field in row["fields"]}
        gold_offsets = set(gold_fields)
        gold_field_count += len(gold_offsets)
        field_by_offset: dict[int, dict[str, Any]] = {}
        for field_index, field in enumerate(predicted_fields, 1):
            where = f"prediction {key[2]} field {field_index}"
            offset = _validate_prediction_field(field, where)
            if offset in field_by_offset:
                raise ValueError(f"{where}: duplicate field offset")
            field_by_offset[offset] = field
            output_field_count += 1
            conflicted_field_count += field.get("status") == "conflicted"
            if offset not in audited:
                unscored_candidate_count += 1
        candidate_offsets = set(field_by_offset) & audited
        candidate_field_count += len(candidate_offsets)
        true_positive_count += len(candidate_offsets & gold_offsets)

        for offset, gold_field in gold_fields.items():
            compatible_types = gold_field.get("compatible_types")
            if compatible_types is None:
                continue
            type_label_count += 1
            predicted_field = field_by_offset.get(offset)
            if not predicted_field or predicted_field.get("status") != "review":
                continue
            candidates = predicted_field.get("type_candidates", [])
            if not isinstance(candidates, list) or len(candidates) != 1:
                continue
            reviewed_type_count += 1
            compatible_type_count += any(
                isinstance(candidate, dict)
                and any(_type_matches(candidate, expected) for expected in compatible_types)
                for candidate in candidates
            )

        for offset, candidate in field_by_offset.items():
            if offset not in audited or candidate.get("status") != "review":
                continue
            reviewed_field_count += 1
            gold_field = gold_fields.get(offset)
            accepted = gold_field is not None
            if accepted and "compatible_types" in gold_field:
                options = gold_field["compatible_types"]
                candidate_types = candidate.get("type_candidates", [])
                accepted = isinstance(candidate_types, list) and len(candidate_types) == 1 and any(
                    isinstance(item, dict)
                    and any(_type_matches(item, expected) for expected in options)
                    for item in candidate_types
                )
            accepted_review_count += accepted

    precision = _ratio(true_positive_count, candidate_field_count)
    recall = _ratio(true_positive_count, gold_field_count)
    return {
        "format": FORMAT,
        "dataset_id": metadata[0],
        "split_id": metadata[1],
        "type_layout_hypotheses_sha256": predictions_sha256,
        "gold_artifact_sha256": gold_sha256,
        "layouts_evaluated": evaluated_layout_count,
        "layouts_missing": sum(key not in predicted_by_key for key in seen_gold),
        "prediction_layouts_present": predicted_layout_count,
        "audited_field_offset_count": sum(len(row["audited_field_offsets"]) for row in gold_rows),
        "gold_field_count": gold_field_count,
        "candidate_field_count": candidate_field_count,
        "unscored_candidate_field_count": unscored_candidate_count,
        "field_offset_true_positives": true_positive_count,
        "field_offset_precision": precision,
        "field_offset_recall": recall,
        "field_offset_f1": _ratio(
            2 * true_positive_count, candidate_field_count + gold_field_count,
        ),
        "compatible_type_labeled_fields": type_label_count,
        "reviewed_type_fields": reviewed_type_count,
        "compatible_type_accuracy": _ratio(compatible_type_count, reviewed_type_count),
        "compatible_type_review_coverage": _ratio(reviewed_type_count, type_label_count),
        "reviewed_fields": reviewed_field_count,
        "accepted_reviewed_fields": accepted_review_count,
        "reviewed_field_acceptance": _ratio(accepted_review_count, reviewed_field_count),
        "high_confidence_reviewer_acceptance": None,
        "high_confidence_reviewer_acceptance_status": "not_evaluated_no_confidence_score",
        "conflicted_layouts": conflicted_layout_count,
        "layout_conflict_rate": _ratio(conflicted_layout_count, predicted_layout_count),
        "conflicted_fields": conflicted_field_count,
        "output_fields": output_field_count,
        "field_conflict_rate": _ratio(conflicted_field_count, output_field_count),
        "prototype_compatibility": None,
        "prototype_compatibility_status": "not_evaluated_no_prototype_hypothesis_input",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("type_layout_hypotheses", type=Path)
    parser.add_argument("gold_layouts", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = evaluate_type_layouts(args.type_layout_hypotheses, args.gold_layouts)
    except ValueError as error:
        parser.error(str(error))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")
    print("layouts evaluated:", result["layouts_evaluated"])
    print("field-offset precision:", result["field_offset_precision"])
    print("field-offset recall:", result["field_offset_recall"])
    print("evaluation:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
