"""Evaluate function prototype hypotheses against independent, scoped gold."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

HYPOTHESIS_FORMAT = "REVENGINSTR.FunctionPrototypeHypothesis/1"
GOLD_FORMAT = "REVENGINSTR.FunctionPrototypeGold/1"
EVALUATION_FORMAT_V1 = "REVENGINSTR.FunctionPrototypeEvaluation/1"
EVALUATION_FORMAT_V2 = "REVENGINSTR.FunctionPrototypeEvaluation/2"
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_PARAMETER_KINDS = {"pointer", "reference", "scalar", "aggregate", "unknown"}
_RETURN_KINDS = _PARAMETER_KINDS | {"void"}
_GOLD_PROPERTIES = {
    "parameter_count", "calling_convention", "return_value", "receiver_parameter_index",
}
_CONFLICT_REASONS = {
    "incompatible_parameter_counts", "calling_convention_conflict", "return_shape_conflict",
    "receiver_identity_conflict", "evidence_conflict", "other",
}


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
        except ValueError as error:
            raise ValueError(f"{path}:{line_no}: invalid JSON: {error}") from error
        if not isinstance(row, dict):
            raise ValueError(f"{path}:{line_no}: expected a JSON object")
        rows.append(row)
    return rows, digest


def _text(value: Any, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{where}: expected a non-empty string")
    return value


def _optional_width(value: Any, where: str) -> None:
    if value is not None and (type(value) is not int or value < 1):
        raise ValueError(f"{where}: width_bytes must be null or a positive integer")


def _validate_architecture(value: Any, where: str) -> None:
    if not isinstance(value, dict) or set(value) != {
        "language_id", "pointer_width_bytes", "endianness",
    }:
        raise ValueError(f"{where}: invalid architecture fields")
    _text(value["language_id"], where)
    if type(value["pointer_width_bytes"]) is not int or value["pointer_width_bytes"] < 1:
        raise ValueError(f"{where}: invalid pointer_width_bytes")
    if not isinstance(value["endianness"], str) or value["endianness"] not in {"little", "big"}:
        raise ValueError(f"{where}: invalid endianness")


def _validate_shape(
    row: Any,
    where: str,
    *,
    gold: bool,
    complete_parameter_indices: set[int] | None = None,
    forbidden_evidence_hashes: set[str] | None = None,
) -> None:
    expected = {"parameter_count", "calling_convention", "parameters", "return_value", "receiver_parameter_index"}
    if gold:
        if not isinstance(row, dict) or set(row) != expected:
            raise ValueError(f"{where}: invalid prototype fields")
    else:
        required = expected | {"candidate_id", "confidence", "evidence_refs"}
        if not isinstance(row, dict) or not required <= set(row) or set(row) - required:
            raise ValueError(f"{where}: invalid hypothesis prototype fields")
    parameter_count = row["parameter_count"]
    if parameter_count is not None and (type(parameter_count) is not int or parameter_count < 0):
        raise ValueError(f"{where}: invalid parameter_count")
    convention = row["calling_convention"]
    if convention is not None:
        _text(convention, where)
    receiver = row["receiver_parameter_index"]
    if receiver is not None and (type(receiver) is not int or receiver < 0):
        raise ValueError(f"{where}: invalid receiver_parameter_index")
    if receiver is not None and parameter_count is not None and receiver >= parameter_count:
        raise ValueError(f"{where}: receiver_parameter_index is outside parameter_count")
    parameters = row["parameters"]
    if not isinstance(parameters, list):
        raise ValueError(f"{where}: parameters must be an array")
    seen_indices = set()
    for index, parameter in enumerate(parameters, 1):
        param_where = f"{where}: parameter {index}"
        allowed_parameter_fields = {"index", "kind", "width_bytes", "target_type_id"}
        if not gold:
            allowed_parameter_fields.add("evidence_refs")
        if not isinstance(parameter, dict) or set(parameter) - allowed_parameter_fields:
            raise ValueError(f"{param_where}: invalid fields")
        if not {"index", "kind", "width_bytes"} <= set(parameter):
            raise ValueError(f"{param_where}: missing index/kind/width")
        param_index = parameter["index"]
        if type(param_index) is not int or param_index < 0 or param_index in seen_indices:
            raise ValueError(f"{param_where}: invalid or duplicate index")
        seen_indices.add(param_index)
        allowed_kinds = _PARAMETER_KINDS
        if not isinstance(parameter["kind"], str) or parameter["kind"] not in allowed_kinds:
            raise ValueError(f"{param_where}: invalid kind")
        _optional_width(parameter["width_bytes"], param_where)
        if "target_type_id" in parameter:
            _text(parameter["target_type_id"], param_where)
            if parameter["kind"] not in {"pointer", "reference"}:
                raise ValueError(f"{param_where}: target_type_id requires pointer or reference")
        if not gold and "evidence_refs" in parameter:
            _validate_evidence_refs(
                parameter["evidence_refs"], param_where, forbidden_evidence_hashes or set(),
            )
    if parameter_count is not None and seen_indices != set(range(parameter_count)):
        raise ValueError(f"{where}: parameter indices do not match parameter_count")
    return_value = row["return_value"]
    if not isinstance(return_value, dict) or set(return_value) - {"kind", "width_bytes", "target_type_id"}:
        raise ValueError(f"{where}: invalid return_value")
    if (
        not {"kind", "width_bytes"} <= set(return_value)
        or not isinstance(return_value["kind"], str)
        or return_value["kind"] not in _RETURN_KINDS
    ):
        raise ValueError(f"{where}: invalid return kind/width")
    _optional_width(return_value["width_bytes"], where)
    if "target_type_id" in return_value:
        _text(return_value["target_type_id"], where)
        if return_value["kind"] not in {"pointer", "reference"}:
            raise ValueError(f"{where}: return target_type_id requires pointer or reference")
    if not gold:
        _text(row["candidate_id"], where)
        confidence = row["confidence"]
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) or not 0 <= confidence <= 1:
            raise ValueError(f"{where}: confidence must be between 0 and 1")
        if not isinstance(row["evidence_refs"], list) or not row["evidence_refs"]:
            raise ValueError(f"{where}: evidence_refs must be non-empty")
        _validate_evidence_refs(
            row["evidence_refs"], where, forbidden_evidence_hashes or set(),
        )
    elif complete_parameter_indices is not None:
        if not complete_parameter_indices <= seen_indices:
            raise ValueError(f"{where}: compatible prototype omits a complete parameter index")


def _validate_evidence_refs(value: Any, where: str, forbidden: set[str]) -> None:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{where}: evidence_refs must be non-empty")
    for index, ref in enumerate(value, 1):
        ref_where = f"{where}: evidence_ref {index}"
        if not isinstance(ref, dict) or set(ref) != {"artifact_sha256", "record_index", "source_format"}:
            raise ValueError(f"{ref_where}: invalid fields")
        digest = ref["artifact_sha256"]
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest) or digest in forbidden:
            raise ValueError(f"{ref_where}: invalid or non-independent artifact_sha256")
        if type(ref["record_index"]) is not int or ref["record_index"] < 1:
            raise ValueError(f"{ref_where}: invalid record_index")
        _text(ref["source_format"], ref_where)


def _validate_gold(row: Any, index: int, *, gold_sha256: str, hypothesis_sha256: str) -> tuple[tuple[str, str, str], dict[str, Any]]:
    where = f"gold record {index}"
    required = {
        "format", "dataset_id", "split_id", "program_id", "program_sha256", "architecture", "function_entry",
        "complete_properties", "complete_parameter_indices", "compatible_prototypes",
        "evidence_refs", "adjudication_status",
    }
    if not isinstance(row, dict) or set(row) != required or row.get("format") != GOLD_FORMAT:
        raise ValueError(f"{where}: unsupported format or fields")
    for key in ("dataset_id", "split_id", "program_id", "function_entry"):
        _text(row[key], where)
    if not isinstance(row["program_sha256"], str) or not _SHA256.fullmatch(row["program_sha256"]):
        raise ValueError(f"{where}: invalid program_sha256")
    _validate_architecture(row["architecture"], where)
    if row["adjudication_status"] != "adjudicated":
        raise ValueError(f"{where}: prototype gold is not adjudicated")
    properties = row["complete_properties"]
    if (
        not isinstance(properties, list)
        or any(not isinstance(value, str) or value not in _GOLD_PROPERTIES for value in properties)
        or len(properties) != len(set(properties))
    ):
        raise ValueError(f"{where}: invalid complete_properties")
    parameter_indices = row["complete_parameter_indices"]
    if not isinstance(parameter_indices, list) or any(type(value) is not int or value < 0 for value in parameter_indices):
        raise ValueError(f"{where}: invalid complete_parameter_indices")
    if len(parameter_indices) != len(set(parameter_indices)):
        raise ValueError(f"{where}: duplicate complete parameter index")
    if not properties and not parameter_indices:
        raise ValueError(f"{where}: gold declares no complete property")
    if not isinstance(row["compatible_prototypes"], list) or not row["compatible_prototypes"]:
        raise ValueError(f"{where}: compatible_prototypes must be non-empty")
    for proto_index, prototype in enumerate(row["compatible_prototypes"], 1):
        _validate_shape(
            prototype, f"{where}: compatible prototype {proto_index}", gold=True,
            complete_parameter_indices=set(parameter_indices),
        )
        for property_name in properties:
            if prototype[property_name] is None:
                raise ValueError(f"{where}: complete property {property_name!r} is unknown")
    _validate_evidence_refs(row["evidence_refs"], where, {gold_sha256, hypothesis_sha256})
    key = (row["program_id"], row["program_sha256"], row["function_entry"])
    return key, row


def _value_matches(candidate: Any, gold: Any) -> bool:
    if isinstance(candidate, dict) and isinstance(gold, dict):
        return all(
            key in candidate and (value is None or candidate[key] == value)
            for key, value in gold.items()
        )
    return candidate == gold


def _shape_matches(
    candidate: dict[str, Any], gold: dict[str, Any],
    properties: set[str], parameter_indices: set[int],
) -> bool:
    if any(not _value_matches(candidate[name], gold[name]) for name in properties):
        return False
    candidate_parameters = {row["index"]: row for row in candidate["parameters"]}
    gold_parameters = {row["index"]: row for row in gold["parameters"]}
    return all(
        index in candidate_parameters
        and index in gold_parameters
        and _value_matches(candidate_parameters[index], gold_parameters[index])
        for index in parameter_indices
    )


def _property_unknown(
    candidate: dict[str, Any], property_name: str, gold_prototypes: list[dict[str, Any]],
    parameter_indices: set[int],
) -> bool:
    def has_known_values(prediction: Any, expected: Any) -> bool:
        if not isinstance(prediction, dict) or not isinstance(expected, dict):
            return prediction is not None
        return all(
            key in prediction and prediction[key] is not None
            and not (key == "kind" and prediction[key] == "unknown")
            for key, value in expected.items() if value is not None
        )

    if property_name == "parameters":
        predictions = {row["index"]: row for row in candidate["parameters"]}
        for index in parameter_indices:
            prediction = predictions.get(index)
            if prediction is None or not any(
                has_known_values(
                    prediction,
                    next(row for row in prototype["parameters"] if row["index"] == index),
                )
                for prototype in gold_prototypes
            ):
                return True
        return False
    if any(
        has_known_values(candidate[property_name], prototype[property_name])
        for prototype in gold_prototypes
    ):
        return False
    return True


def evaluate_prototypes(
    hypotheses_path: Path, gold_path: Path, *, minimum_confidence: float = 0.95,
    format_version: int = 1,
) -> dict[str, Any]:
    """Score compatible candidates only on properties explicitly complete in gold."""
    if isinstance(minimum_confidence, bool) or not isinstance(minimum_confidence, (int, float)) or not 0 <= minimum_confidence <= 1:
        raise ValueError("minimum_confidence must be between 0 and 1")
    if type(format_version) is not int or format_version not in {1, 2}:
        raise ValueError("format_version must be 1 or 2")
    hypotheses, hypotheses_sha256 = _read_jsonl(hypotheses_path)
    gold_rows, gold_sha256 = _read_jsonl(gold_path)
    hypothesis_by_key = {}
    for index, row in enumerate(hypotheses, 1):
        where = f"hypothesis record {index}"
        if not isinstance(row, dict) or row.get("format") != HYPOTHESIS_FORMAT:
            raise ValueError(f"{where}: expected {HYPOTHESIS_FORMAT}")
        for key in ("program_id", "function_entry"):
            _text(row.get(key), where)
        digest = row.get("program_sha256")
        if not isinstance(digest, str) or not _SHA256.fullmatch(digest):
            raise ValueError(f"{where}: invalid program_sha256")
        _validate_architecture(row.get("architecture"), where)
        key = (row["program_id"], digest, row["function_entry"])
        if key in hypothesis_by_key:
            raise ValueError(f"{where}: duplicate function identity")
        if not isinstance(row.get("status"), str) or row["status"] not in {"candidate", "review", "conflicted"}:
            raise ValueError(f"{where}: invalid status")
        if not isinstance(row.get("candidates"), list):
            raise ValueError(f"{where}: candidates must be an array")
        conflicts = row.get("conflicts")
        if not isinstance(conflicts, list) or (row["status"] == "conflicted" and not conflicts):
            raise ValueError(f"{where}: conflicted status requires conflict evidence")
        for conflict_index, conflict in enumerate(conflicts, 1):
            conflict_where = f"{where}: conflict {conflict_index}"
            if (
                not isinstance(conflict, dict)
                or set(conflict) != {"reason", "evidence_refs"}
                or not isinstance(conflict["reason"], str)
                or conflict["reason"] not in _CONFLICT_REASONS
            ):
                raise ValueError(f"{conflict_where}: invalid conflict")
            _validate_evidence_refs(
                conflict["evidence_refs"], conflict_where,
                {hypotheses_sha256, gold_sha256},
            )
        candidate_ids = set()
        for candidate_index, candidate in enumerate(row["candidates"], 1):
            candidate_where = f"{where}: candidate {candidate_index}"
            _validate_shape(
                candidate, candidate_where, gold=False,
                forbidden_evidence_hashes={hypotheses_sha256, gold_sha256},
            )
            if candidate["candidate_id"] in candidate_ids:
                raise ValueError(f"{candidate_where}: duplicate candidate_id")
            candidate_ids.add(candidate["candidate_id"])
        hypothesis_by_key[key] = row
    if not gold_rows:
        raise ValueError("gold input is empty")

    metadata: tuple[str, str] | None = None
    seen_gold = set()
    missing_count = hypothesis_count = 0
    candidate_count = high_confidence_count = compatible_count = 0
    high_confidence_functions = high_confidence_correct_functions = 0
    conflict_count = 0
    property_counts = {
        name: {"scored": 0, "compatible": 0, "unknown": 0}
        for name in sorted(_GOLD_PROPERTIES | {"parameters"})
    }
    for index, raw in enumerate(gold_rows, 1):
        key, gold = _validate_gold(
            raw, index, gold_sha256=gold_sha256, hypothesis_sha256=hypotheses_sha256,
        )
        if key in seen_gold:
            raise ValueError(f"gold record {index}: duplicate function identity")
        seen_gold.add(key)
        current_metadata = (gold["dataset_id"], gold["split_id"])
        if metadata is None:
            metadata = current_metadata
        elif metadata != current_metadata:
            raise ValueError(f"gold record {index}: mixed dataset or split identity")
        hypothesis = hypothesis_by_key.get(key)
        if hypothesis is None:
            missing_count += 1
            continue
        if hypothesis["architecture"] != gold["architecture"]:
            raise ValueError(f"gold record {index}: architecture disagrees with hypothesis")
        hypothesis_count += 1
        conflict_count += hypothesis["status"] == "conflicted"
        properties = set(gold["complete_properties"])
        complete_parameters = set(gold["complete_parameter_indices"])
        function_high_confidence = []
        for candidate in hypothesis["candidates"]:
            candidate_count += 1
            candidate_matches = [
                _shape_matches(candidate, compatible, properties, complete_parameters)
                for compatible in gold["compatible_prototypes"]
            ]
            accepted = any(candidate_matches)
            if (
                hypothesis["status"] != "conflicted"
                and candidate["confidence"] >= minimum_confidence
            ):
                high_confidence_count += 1
                compatible_count += accepted
                function_high_confidence.append((candidate, accepted))
            for property_name in properties:
                property_counts[property_name]["scored"] += 1
                property_counts[property_name]["compatible"] += any(
                    _value_matches(candidate[property_name], proto[property_name])
                    for proto in gold["compatible_prototypes"]
                )
                property_counts[property_name]["unknown"] += _property_unknown(
                    candidate, property_name, gold["compatible_prototypes"], complete_parameters,
                )
            if complete_parameters:
                params_match = any(
                    _shape_matches(candidate, proto, set(), complete_parameters)
                    for proto in gold["compatible_prototypes"]
                )
                property_counts["parameters"]["scored"] += 1
                property_counts["parameters"]["compatible"] += params_match
                property_counts["parameters"]["unknown"] += _property_unknown(
                    candidate, "parameters", gold["compatible_prototypes"], complete_parameters,
                )
        if function_high_confidence:
            high_confidence_functions += 1
            best_confidence = max(item[0]["confidence"] for item in function_high_confidence)
            best = [item for item in function_high_confidence if item[0]["confidence"] == best_confidence]
            if len(best) == 1:
                high_confidence_correct_functions += best[0][1]

    if metadata is None:
        raise ValueError("gold input is empty")
    per_property = {}
    for name, counts in sorted(property_counts.items()):
        if not counts["scored"]:
            continue
        metrics = {
            key: value for key, value in counts.items()
            if format_version == 2 or key != "unknown"
        }
        metrics["accuracy"] = counts["compatible"] / counts["scored"]
        if format_version == 2:
            known = counts["scored"] - counts["unknown"]
            metrics["coverage"] = known / counts["scored"]
            metrics["known_accuracy"] = counts["compatible"] / known if known else None
        per_property[name] = metrics
    return {
        "format": EVALUATION_FORMAT_V1 if format_version == 1 else EVALUATION_FORMAT_V2,
        "dataset_id": metadata[0],
        "split_id": metadata[1],
        "function_prototype_hypotheses_sha256": hypotheses_sha256,
        "gold_artifact_sha256": gold_sha256,
        "functions_evaluated": len(seen_gold),
        "hypotheses_present": hypothesis_count,
        "hypotheses_missing": missing_count,
        "candidate_count": candidate_count,
        "minimum_confidence": minimum_confidence,
        "high_confidence_candidate_count": high_confidence_count,
        "high_confidence_compatible_candidates": compatible_count,
        "high_confidence_candidate_compatibility": compatible_count / high_confidence_count if high_confidence_count else None,
        "high_confidence_function_count": high_confidence_functions,
        "high_confidence_function_coverage": high_confidence_functions / len(seen_gold) if seen_gold else None,
        "top_candidate_compatibility": high_confidence_correct_functions / high_confidence_functions if high_confidence_functions else None,
        "conflicted_hypotheses": conflict_count,
        "hypothesis_conflict_rate": conflict_count / hypothesis_count if hypothesis_count else None,
        "per_property": per_property,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("prototype_hypotheses", type=Path)
    parser.add_argument("gold_prototypes", type=Path)
    parser.add_argument("--minimum-confidence", type=float, default=0.95)
    parser.add_argument("--format-version", type=int, choices=(1, 2), default=1)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = evaluate_prototypes(
            args.prototype_hypotheses, args.gold_prototypes,
            minimum_confidence=args.minimum_confidence, format_version=args.format_version,
        )
    except ValueError as error:
        parser.error(str(error))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, sort_keys=True) + "\n", encoding="utf-8")
    print("functions evaluated:", result["functions_evaluated"])
    print("high-confidence compatibility:", result["high_confidence_candidate_compatibility"])
    print("evaluation:", args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
