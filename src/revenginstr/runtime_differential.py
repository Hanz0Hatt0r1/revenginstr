"""Compare two pinned runtime/static reports for one declared intervention."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

MANIFEST_FORMAT = "REVENGINSTR.RuntimeDifferentialManifest/1"
CORRELATION_FORMAT = "REVENGINSTR.RuntimeStaticCorrelation/1"
REPORT_FORMAT = "REVENGINSTR.RuntimeDifferential/1"
MAX_EVENTS = 100_000
MAX_SIGNATURES = MAX_EVENTS * 2
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{1,16}$")
_DELTA = re.compile(r"^-?0x[0-9a-fA-F]{1,16}$")
_MAX_SEQUENCE = 1_000_000_000
_REPORT_FIELDS = {
    "format", "capture_id", "program_id", "program_sha256", "static_identity_sha256",
    "semantic_graph_sha256", "capture_manifest_sha256", "observations_sha256",
    "address_mapping", "sampling", "summary", "events",
}
_EVENT_FIELDS = {
    "capture_id", "sequence", "event_kind", "runtime_address", "normalized_address",
    "match_state", "matched_node_ids", "function_entries",
}


class DifferentialError(ValueError):
    """Runtime reports or intervention metadata cannot be compared safely."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON object key {key!r}")
        result[key] = value
    return result


def _read_json(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise DifferentialError(f"{path}: invalid JSON: {error}") from error
    if not isinstance(value, dict):
        raise DifferentialError(f"{path}: expected a JSON object")
    return value, raw


def _sha256(value: Any, where: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise DifferentialError(f"{where}: expected lowercase SHA-256")
    return value


def _validate_manifest(value: dict[str, Any]) -> dict[str, Any]:
    expected = {
        "format", "comparison_id", "baseline_report_sha256", "treatment_report_sha256", "intervention",
    }
    if set(value) != expected or value.get("format") != MANIFEST_FORMAT:
        raise DifferentialError("unsupported or malformed runtime differential manifest")
    for key in ("comparison_id",):
        if not isinstance(value[key], str) or not value[key].strip():
            raise DifferentialError(f"manifest: invalid {key}")
    for key in ("baseline_report_sha256", "treatment_report_sha256"):
        _sha256(value[key], f"manifest {key}")
    intervention = value["intervention"]
    fields = {"dimension", "name", "baseline_label", "treatment_label", "fixed_context_sha256"}
    if not isinstance(intervention, dict) or set(intervention) != fields:
        raise DifferentialError("manifest: malformed intervention")
    if not isinstance(intervention["dimension"], str) or intervention["dimension"] not in {"input", "state", "action"}:
        raise DifferentialError("manifest: unsupported intervention dimension")
    for key in ("name", "baseline_label", "treatment_label"):
        item = intervention[key]
        if not isinstance(item, str) or not item.strip() or len(item) > 256:
            raise DifferentialError(f"manifest intervention: invalid {key}")
    if intervention["baseline_label"] == intervention["treatment_label"]:
        raise DifferentialError("manifest intervention labels must differ")
    _sha256(intervention["fixed_context_sha256"], "manifest fixed_context_sha256")
    return intervention


def _validate_report(value: dict[str, Any], label: str) -> None:
    if set(value) != _REPORT_FIELDS or value.get("format") != CORRELATION_FORMAT:
        raise DifferentialError(f"{label}: expected {CORRELATION_FORMAT}")
    for key in (
        "program_sha256", "semantic_graph_sha256", "static_identity_sha256",
        "capture_manifest_sha256", "observations_sha256",
    ):
        _sha256(value.get(key), f"{label} {key}")
    for key in ("capture_id", "program_id"):
        if not isinstance(value.get(key), str) or not value[key]:
            raise DifferentialError(f"{label}: invalid {key}")
    mapping = value.get("address_mapping")
    if (
        not isinstance(mapping, dict)
        or set(mapping) != {"method", "runtime_module_base", "static_image_base", "module_delta"}
        or mapping.get("method") != "runtime_address_minus_module_delta"
        or not isinstance(mapping.get("runtime_module_base"), str)
        or _ADDRESS.fullmatch(mapping["runtime_module_base"]) is None
        or not isinstance(mapping.get("static_image_base"), str)
        or _ADDRESS.fullmatch(mapping["static_image_base"]) is None
        or not isinstance(mapping.get("module_delta"), str)
        or _DELTA.fullmatch(mapping["module_delta"]) is None
    ):
        raise DifferentialError(f"{label}: invalid address mapping")
    runtime_base = int(mapping["runtime_module_base"], 16)
    static_base = int(mapping["static_image_base"], 16)
    expected_delta = runtime_base - static_base
    delta_text = mapping["module_delta"]
    parsed_delta = int(delta_text[1:] if delta_text.startswith("-") else delta_text, 16)
    if delta_text.startswith("-"):
        parsed_delta = -parsed_delta
    if parsed_delta != expected_delta:
        raise DifferentialError(f"{label}: module_delta does not match its image bases")
    sampling = value.get("sampling")
    if (
        not isinstance(sampling, dict)
        or set(sampling) != {"status", "gaps"}
        or not isinstance(sampling.get("status"), str)
        or sampling["status"] not in {"complete", "sampled", "unknown"}
        or not isinstance(sampling.get("gaps"), list)
        or len(sampling["gaps"]) > 10_000
    ):
        raise DifferentialError(f"{label}: invalid sampling metadata")
    previous_last = -1
    for gap_index, gap in enumerate(sampling["gaps"], 1):
        if not isinstance(gap, dict) or set(gap) != {"first_sequence", "last_sequence", "reason"}:
            raise DifferentialError(f"{label}: invalid sampling gap {gap_index}")
        first, last, reason = gap["first_sequence"], gap["last_sequence"], gap["reason"]
        if (
            isinstance(first, bool) or not isinstance(first, int) or not 0 <= first <= _MAX_SEQUENCE
            or isinstance(last, bool) or not isinstance(last, int) or not first <= last <= _MAX_SEQUENCE
            or not isinstance(reason, str) or not reason.strip() or first <= previous_last
        ):
            raise DifferentialError(f"{label}: invalid or overlapping sampling gap {gap_index}")
        previous_last = last
    if sampling["status"] == "complete" and sampling["gaps"]:
        raise DifferentialError(f"{label}: complete sampling cannot declare gaps")
    if sampling["status"] == "sampled" and not sampling["gaps"]:
        raise DifferentialError(f"{label}: sampled sampling must declare gaps")
    events = value.get("events")
    if not isinstance(events, list) or not 1 <= len(events) <= MAX_EVENTS:
        raise DifferentialError(f"{label}: events must be a non-empty bounded array")
    sequences: set[int] = set()
    state_counts: Counter[str] = Counter()
    for index, event in enumerate(events, 1):
        if not isinstance(event, dict) or set(event) != _EVENT_FIELDS:
            raise DifferentialError(f"{label} event {index}: unexpected fields")
        if event["capture_id"] != value["capture_id"]:
            raise DifferentialError(f"{label} event {index}: capture_id mismatch")
        sequence = event["sequence"]
        if (
            isinstance(sequence, bool) or not isinstance(sequence, int)
            or not 0 <= sequence <= _MAX_SEQUENCE or sequence in sequences
        ):
            raise DifferentialError(f"{label} event {index}: invalid or duplicate sequence")
        sequences.add(sequence)
        runtime_address = event["runtime_address"]
        if not isinstance(runtime_address, str) or re.fullmatch(r"(?:0x)?[0-9a-fA-F]{1,16}", runtime_address) is None:
            raise DifferentialError(f"{label} event {index}: invalid runtime_address")
        address = event.get("normalized_address")
        if address is not None and (not isinstance(address, str) or _ADDRESS.fullmatch(address) is None):
            raise DifferentialError(f"{label} event {index}: invalid normalized_address")
        if (
            not isinstance(event.get("event_kind"), str)
            or event["event_kind"] not in {"function_entry", "function_exit", "call_target", "instruction"}
        ):
            raise DifferentialError(f"{label} event {index}: invalid event_kind")
        if (
            not isinstance(event.get("function_entries"), list)
            or not all(isinstance(item, str) and item for item in event["function_entries"])
            or len(event["function_entries"]) != len(set(event["function_entries"]))
            or not isinstance(event.get("matched_node_ids"), list)
            or not all(isinstance(item, str) and item for item in event["matched_node_ids"])
            or len(event["matched_node_ids"]) != len(set(event["matched_node_ids"]))
        ):
            raise DifferentialError(f"{label} event {index}: invalid static match data")
        state = event["match_state"]
        if not isinstance(state, str) or state not in {
            "matched", "ambiguous", "unmatched", "mapping_underflow", "mapping_overflow",
        }:
            raise DifferentialError(f"{label} event {index}: invalid match_state")
        state_counts[state] += 1
        if state in {"mapping_underflow", "mapping_overflow"}:
            if address is not None or event["matched_node_ids"] or event["function_entries"]:
                raise DifferentialError(f"{label} event {index}: invalid out-of-range match")
        elif address is None:
            raise DifferentialError(f"{label} event {index}: mapped event has no normalized_address")
        nodes = event["matched_node_ids"]
        if (
            state == "matched" and len(nodes) != 1
            or state == "ambiguous" and len(nodes) < 2
            or state in {"unmatched", "mapping_underflow", "mapping_overflow"} and nodes
        ):
            raise DifferentialError(f"{label} event {index}: match_state conflicts with matched nodes")
        numeric_runtime = int(runtime_address, 16)
        numeric_delta = parsed_delta
        numeric_normalized = numeric_runtime - numeric_delta
        expected_state = "mapping_underflow" if numeric_normalized < 0 else "mapping_overflow" if numeric_normalized > (1 << 64) - 1 else None
        if expected_state is None:
            if address is None or int(address, 16) != numeric_normalized:
                raise DifferentialError(f"{label} event {index}: normalized_address conflicts with mapping")
        elif state != expected_state:
            raise DifferentialError(f"{label} event {index}: match_state conflicts with address mapping")

    summary = value.get("summary")
    if (
        not isinstance(summary, dict)
        or set(summary) != {
            "event_count", "matched_count", "ambiguous_count", "unmatched_count",
            "mapping_underflow_count", "mapping_overflow_count",
        }
        or any(isinstance(count, bool) or not isinstance(count, int) or count < 0 for count in summary.values())
        or summary.get("event_count") != len(events)
        or summary.get("matched_count") != state_counts["matched"]
        or summary.get("ambiguous_count") != state_counts["ambiguous"]
        or summary.get("unmatched_count") != state_counts["unmatched"]
        or summary.get("mapping_underflow_count") != state_counts["mapping_underflow"]
        or summary.get("mapping_overflow_count") != state_counts["mapping_overflow"]
    ):
        raise DifferentialError(f"{label}: summary does not match its events")


def compare_reports(
    baseline: dict[str, Any], treatment: dict[str, Any], manifest: dict[str, Any], *,
    baseline_sha256: str, treatment_sha256: str, manifest_sha256: str,
) -> dict[str, Any]:
    intervention = _validate_manifest(manifest)
    _validate_report(baseline, "baseline report")
    _validate_report(treatment, "treatment report")
    baseline_sha256 = _sha256(baseline_sha256, "baseline report SHA-256")
    treatment_sha256 = _sha256(treatment_sha256, "treatment report SHA-256")
    manifest_sha256 = _sha256(manifest_sha256, "manifest SHA-256")
    if baseline_sha256 != manifest["baseline_report_sha256"]:
        raise DifferentialError("manifest does not pin the baseline report")
    if treatment_sha256 != manifest["treatment_report_sha256"]:
        raise DifferentialError("manifest does not pin the treatment report")
    identity_fields = ("program_id", "program_sha256", "semantic_graph_sha256", "static_identity_sha256")
    if any(baseline[field] != treatment[field] for field in identity_fields):
        raise DifferentialError("runtime reports do not share one exact static identity")
    if baseline["capture_id"] == treatment["capture_id"]:
        raise DifferentialError("baseline and treatment capture ids must differ")
    if int(baseline["address_mapping"]["static_image_base"], 16) != int(treatment["address_mapping"]["static_image_base"], 16):
        raise DifferentialError("runtime reports use different static image bases")

    def index(report: dict[str, Any]) -> tuple[Counter[tuple[str, str]], dict[tuple[str, str], tuple[list[str], list[str]]]]:
        counts: Counter[tuple[str, str]] = Counter()
        nodes: dict[tuple[str, str], tuple[set[str], set[str]]] = {}
        for event in report["events"]:
            address = event["normalized_address"]
            if address is None:
                continue
            key = event["event_kind"], f"0x{int(address, 16):x}"
            counts[key] += 1
            node_ids, entries = nodes.setdefault(key, (set(), set()))
            node_ids.update(event["matched_node_ids"])
            entries.update(event["function_entries"])
        return counts, {key: (sorted(ids), sorted(entries)) for key, (ids, entries) in nodes.items()}

    before, before_nodes = index(baseline)
    after, after_nodes = index(treatment)
    candidates = []
    for key in sorted(set(before) | set(after)):
        old, new = before[key], after[key]
        if old == new:
            continue
        node_ids, entries = (
            sorted(set(before_nodes.get(key, ([], []))[0]) | set(after_nodes.get(key, ([], []))[0])),
            sorted(set(before_nodes.get(key, ([], []))[1]) | set(after_nodes.get(key, ([], []))[1])),
        )
        candidates.append({
            "event_kind": key[0],
            "normalized_address": key[1],
            "baseline_count": old,
            "treatment_count": new,
            "delta": new - old,
            "change": "added" if old == 0 else "removed" if new == 0 else "increased" if new > old else "decreased",
            "matched_node_ids": node_ids,
            "function_entries": entries,
            "evidence_class": "correlation",
        })
    candidates.sort(key=lambda item: (-abs(item["delta"]), item["normalized_address"], item["event_kind"]))
    if len(candidates) > MAX_SIGNATURES:
        raise DifferentialError(f"changed signatures exceed {MAX_SIGNATURES}")
    for rank, candidate in enumerate(candidates, 1):
        candidate["rank"] = rank
    return {
        "format": REPORT_FORMAT,
        "comparison_id": manifest["comparison_id"],
        "program_id": baseline["program_id"],
        "program_sha256": baseline["program_sha256"],
        "semantic_graph_sha256": baseline["semantic_graph_sha256"],
        "static_identity_sha256": baseline["static_identity_sha256"],
        "baseline_capture_id": baseline["capture_id"],
        "treatment_capture_id": treatment["capture_id"],
        "baseline_report_sha256": baseline_sha256,
        "treatment_report_sha256": treatment_sha256,
        "manifest_sha256": manifest_sha256,
        "intervention": intervention,
        "sampling": {"baseline": baseline["sampling"], "treatment": treatment["sampling"]},
        "summary": {
            "baseline_event_count": len(baseline["events"]),
            "treatment_event_count": len(treatment["events"]),
            "baseline_unmapped_count": sum(event["normalized_address"] is None for event in baseline["events"]),
            "treatment_unmapped_count": sum(event["normalized_address"] is None for event in treatment["events"]),
            "changed_signature_count": len(candidates),
        },
        "ranked_candidates": candidates,
    }


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def compare_files(baseline_path: Path, treatment_path: Path, manifest_path: Path, output_path: Path) -> dict[str, Any]:
    paths = [path.resolve() for path in (baseline_path, treatment_path, manifest_path)]
    output_path = output_path.resolve()
    if output_path in paths:
        raise DifferentialError("output path must not replace an input")
    baseline, baseline_raw = _read_json(paths[0])
    treatment, treatment_raw = _read_json(paths[1])
    manifest, manifest_raw = _read_json(paths[2])
    result = compare_reports(
        baseline, treatment, manifest,
        baseline_sha256=hashlib.sha256(baseline_raw).hexdigest(),
        treatment_sha256=hashlib.sha256(treatment_raw).hexdigest(),
        manifest_sha256=hashlib.sha256(manifest_raw).hexdigest(),
    )
    _write_json(output_path, result)
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", type=Path)
    parser.add_argument("treatment", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        result = compare_files(args.baseline, args.treatment, args.manifest, args.output)
    except (DifferentialError, OSError) as error:
        parser.exit(2, f"runtime differential failed: {error}\n")
    print("changed signatures:", result["summary"]["changed_signature_count"])
    print("output:", args.output.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
