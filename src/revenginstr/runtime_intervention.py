"""Aggregate repeated, pinned runtime differential reports."""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path
from statistics import median
from typing import Any

MANIFEST_FORMAT = "REVENGINSTR.RuntimeInterventionManifest/1"
DIFFERENTIAL_FORMAT = "REVENGINSTR.RuntimeDifferential/1"
REPORT_FORMAT = "REVENGINSTR.RuntimeInterventionEvidence/1"
MIN_REPETITIONS = 3
MAX_REPETITIONS = 100
MAX_CANDIDATE_ROWS = 200_000
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_ADDRESS = re.compile(r"^0x[0-9a-f]{1,16}$")
_INTERVENTION_FIELDS = {"dimension", "name", "baseline_label", "treatment_label", "fixed_context_sha256"}
_MANIFEST_FIELDS = {"format", "collection_id", "intervention", "observation_window_sha256", "comparisons"}
_DIFFERENTIAL_FIELDS = {
    "format", "comparison_id", "program_id", "program_sha256", "semantic_graph_sha256",
    "static_identity_sha256", "baseline_capture_id", "treatment_capture_id",
    "baseline_report_sha256", "treatment_report_sha256", "manifest_sha256", "intervention",
    "sampling", "summary", "ranked_candidates",
}


class InterventionError(ValueError):
    """Repeated runtime reports do not form one safe comparison set."""


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
        raise InterventionError(f"{path}: invalid JSON: {error}") from error
    if not isinstance(value, dict):
        raise InterventionError(f"{path}: expected a JSON object")
    return value, raw


def _sha256(value: Any, where: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise InterventionError(f"{where}: expected lowercase SHA-256")
    return value


def _validate_intervention(value: Any, where: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _INTERVENTION_FIELDS:
        raise InterventionError(f"{where}: malformed intervention")
    if not isinstance(value["dimension"], str) or value["dimension"] not in {"input", "state", "action"}:
        raise InterventionError(f"{where}: unsupported dimension")
    for key in ("name", "baseline_label", "treatment_label"):
        if not isinstance(value[key], str) or not value[key].strip() or len(value[key]) > 256:
            raise InterventionError(f"{where}: invalid {key}")
    if value["baseline_label"] == value["treatment_label"]:
        raise InterventionError(f"{where}: labels must differ")
    _sha256(value["fixed_context_sha256"], f"{where} fixed_context_sha256")
    return value


def _validate_manifest(value: dict[str, Any]) -> tuple[str, dict[str, Any], str, list[dict[str, str]]]:
    if set(value) != _MANIFEST_FIELDS or value.get("format") != MANIFEST_FORMAT:
        raise InterventionError("unsupported or malformed intervention manifest")
    collection_id = value["collection_id"]
    if not isinstance(collection_id, str) or not collection_id.strip():
        raise InterventionError("manifest: invalid collection_id")
    intervention = _validate_intervention(value["intervention"], "manifest intervention")
    observation_window_sha256 = _sha256(value["observation_window_sha256"], "manifest observation_window_sha256")
    comparisons = value["comparisons"]
    if not isinstance(comparisons, list) or not MIN_REPETITIONS <= len(comparisons) <= MAX_REPETITIONS:
        raise InterventionError(f"manifest: expected {MIN_REPETITIONS} to {MAX_REPETITIONS} comparisons")
    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    normalized = []
    for index, item in enumerate(comparisons, 1):
        if not isinstance(item, dict) or set(item) != {"comparison_id", "report_path", "report_sha256"}:
            raise InterventionError(f"manifest comparison {index}: malformed entry")
        comparison_id, report_path = item["comparison_id"], item["report_path"]
        if not isinstance(comparison_id, str) or not comparison_id.strip() or comparison_id in seen_ids:
            raise InterventionError(f"manifest comparison {index}: invalid or duplicate comparison_id")
        if not isinstance(report_path, str) or not report_path.strip() or report_path in seen_paths:
            raise InterventionError(f"manifest comparison {index}: invalid or duplicate report_path")
        seen_ids.add(comparison_id)
        seen_paths.add(report_path)
        normalized.append({
            "comparison_id": comparison_id,
            "report_path": report_path,
            "report_sha256": _sha256(item["report_sha256"], f"manifest comparison {index} report_sha256"),
        })
    return collection_id, intervention, observation_window_sha256, normalized


def _validate_differential(value: dict[str, Any], comparison_id: str) -> None:
    if set(value) != _DIFFERENTIAL_FIELDS or value.get("format") != DIFFERENTIAL_FORMAT:
        raise InterventionError(f"comparison {comparison_id}: invalid differential report")
    if value.get("comparison_id") != comparison_id:
        raise InterventionError(f"comparison {comparison_id}: id does not match manifest")
    for key in (
        "program_sha256", "semantic_graph_sha256", "static_identity_sha256", "baseline_report_sha256",
        "treatment_report_sha256", "manifest_sha256",
    ):
        _sha256(value.get(key), f"comparison {comparison_id} {key}")
    for key in ("program_id", "baseline_capture_id", "treatment_capture_id"):
        if not isinstance(value.get(key), str) or not value[key].strip():
            raise InterventionError(f"comparison {comparison_id}: invalid {key}")
    if value["baseline_capture_id"] == value["treatment_capture_id"]:
        raise InterventionError(f"comparison {comparison_id}: capture ids must differ")
    sampling = value["sampling"]
    if (
        not isinstance(sampling, dict) or set(sampling) != {"baseline", "treatment"}
        or any(
            not isinstance(sampling.get(side), dict)
            or set(sampling[side]) != {"status", "gaps"}
            or not isinstance(sampling[side]["status"], str)
            or sampling[side]["status"] not in {"complete", "sampled", "unknown"}
            or not isinstance(sampling[side]["gaps"], list)
            for side in ("baseline", "treatment")
        )
    ):
        raise InterventionError(f"comparison {comparison_id}: invalid sampling metadata")
    for side in ("baseline", "treatment"):
        sample = sampling[side]
        if sample["status"] == "complete" and sample["gaps"] or sample["status"] == "sampled" and not sample["gaps"]:
            raise InterventionError(f"comparison {comparison_id}: sampling status conflicts with gaps")
    summary = value["summary"]
    candidates = value["ranked_candidates"]
    if (
        not isinstance(summary, dict)
        or not isinstance(summary.get("changed_signature_count"), int)
        or isinstance(summary["changed_signature_count"], bool)
        or not isinstance(candidates, list)
        or len(candidates) > MAX_CANDIDATE_ROWS
        or summary["changed_signature_count"] != len(candidates)
    ):
        raise InterventionError(f"comparison {comparison_id}: invalid candidate summary")
    seen_signatures: set[tuple[str, str]] = set()
    for index, candidate in enumerate(candidates, 1):
        if not isinstance(candidate, dict):
            raise InterventionError(f"comparison {comparison_id} candidate {index}: expected object")
        kind, address, delta = candidate.get("event_kind"), candidate.get("normalized_address"), candidate.get("delta")
        baseline_count, treatment_count = candidate.get("baseline_count"), candidate.get("treatment_count")
        if (
            not isinstance(kind, str) or kind not in {"function_entry", "function_exit", "call_target", "instruction"}
            or not isinstance(address, str) or _ADDRESS.fullmatch(address) is None
            or isinstance(delta, bool) or not isinstance(delta, int) or delta == 0
            or abs(delta) > 100_000
            or isinstance(baseline_count, bool) or not isinstance(baseline_count, int) or not 0 <= baseline_count <= 100_000
            or isinstance(treatment_count, bool) or not isinstance(treatment_count, int) or not 0 <= treatment_count <= 100_000
            or candidate.get("evidence_class") != "correlation"
            or baseline_count + delta != treatment_count
            or not isinstance(candidate.get("matched_node_ids"), list)
            or not isinstance(candidate.get("function_entries"), list)
            or not all(isinstance(item, str) and item for item in candidate["matched_node_ids"] + candidate["function_entries"])
        ):
            raise InterventionError(f"comparison {comparison_id} candidate {index}: invalid candidate")
        signature = kind, address
        if signature in seen_signatures:
            raise InterventionError(f"comparison {comparison_id}: duplicate candidate signature")
        seen_signatures.add(signature)


def compare_files(manifest_path: Path, output_path: Path) -> dict[str, Any]:
    manifest_path = manifest_path.resolve()
    manifest, manifest_raw = _read_json(manifest_path)
    collection_id, intervention, observation_window_sha256, comparisons = _validate_manifest(manifest)
    root = manifest_path.parent.resolve()
    output_path = output_path.resolve()
    if output_path == manifest_path:
        raise InterventionError("output path must not replace the manifest")

    reports: list[dict[str, Any]] = []
    paths = {manifest_path}
    candidate_rows = 0
    for item in comparisons:
        report_path = (root / item["report_path"]).resolve()
        if not report_path.is_relative_to(root):
            raise InterventionError(f"comparison {item['comparison_id']}: report path escapes manifest directory")
        if output_path == report_path:
            raise InterventionError("output path must not replace an input report")
        if report_path in paths:
            raise InterventionError("input paths must be distinct")
        paths.add(report_path)
        report, raw = _read_json(report_path)
        if hashlib.sha256(raw).hexdigest() != item["report_sha256"]:
            raise InterventionError(f"comparison {item['comparison_id']}: report hash mismatch")
        _validate_differential(report, item["comparison_id"])
        candidate_rows += len(report["ranked_candidates"])
        if candidate_rows > MAX_CANDIDATE_ROWS:
            raise InterventionError(f"aggregate candidate rows exceed {MAX_CANDIDATE_ROWS}")
        if report["intervention"] != intervention:
            raise InterventionError(f"comparison {item['comparison_id']}: intervention differs from manifest")
        report["_report_sha256"] = item["report_sha256"]
        reports.append(report)

    identity_fields = ("program_id", "program_sha256", "semantic_graph_sha256", "static_identity_sha256")
    identity = {field: reports[0][field] for field in identity_fields}
    for report in reports[1:]:
        if any(report[field] != identity[field] for field in identity_fields):
            raise InterventionError("comparison reports do not share one exact static identity")

    capture_ids: set[str] = set()
    source_hashes: set[str] = set()
    complete_pairs = 0
    sampling = []
    for report in reports:
        for key in ("baseline_capture_id", "treatment_capture_id"):
            capture_id = report[key]
            if capture_id in capture_ids:
                raise InterventionError("repeated comparisons must use distinct capture ids")
            capture_ids.add(capture_id)
        for key in ("baseline_report_sha256", "treatment_report_sha256"):
            source_hash = report[key]
            if source_hash in source_hashes:
                raise InterventionError("repeated comparisons must use distinct source correlation reports")
            source_hashes.add(source_hash)
        complete = all(report["sampling"][side]["status"] == "complete" and not report["sampling"][side]["gaps"] for side in ("baseline", "treatment"))
        complete_pairs += complete
        sampling.append({
            "comparison_id": report["comparison_id"],
            "baseline_status": report["sampling"]["baseline"]["status"],
            "treatment_status": report["sampling"]["treatment"]["status"],
            "complete": complete,
        })

    signatures: dict[tuple[str, str], dict[int, dict[str, Any]]] = defaultdict(dict)
    for pair_index, report in enumerate(reports):
        for candidate in report["ranked_candidates"]:
            key = candidate["event_kind"], candidate["normalized_address"]
            signatures[key][pair_index] = candidate

    candidates = []
    all_complete = complete_pairs == len(reports)
    for (event_kind, address), pair_candidates in signatures.items():
        observed = sorted(pair_candidates.items())
        deltas = [0] * len(reports)
        for pair_index, candidate in observed:
            deltas[pair_index] = candidate["delta"]
        positive = sum(delta > 0 for delta in deltas)
        negative = sum(delta < 0 for delta in deltas)
        unchanged = len(reports) - positive - negative
        dominant = max(positive, negative)
        supported = len(reports) >= MIN_REPETITIONS and all_complete and dominant == len(reports)
        candidates.append({
            "event_kind": event_kind,
            "normalized_address": address,
            "direction": "mixed" if positive and negative else "increase" if positive else "decrease",
            "pair_count": len(reports),
            "positive_pair_count": positive,
            "negative_pair_count": negative,
            "unchanged_pair_count": unchanged,
            "support_repetition_count": dominant,
            "support_fraction": dominant / len(reports),
            "median_delta": median(deltas),
            "pairwise_deltas": [
                {"comparison_id": reports[pair_index]["comparison_id"], "delta": candidate["delta"]}
                for pair_index, candidate in observed
            ],
            "matched_node_ids": sorted({
                node_id for candidate in pair_candidates.values() for node_id in candidate["matched_node_ids"]
            }),
            "function_entries": sorted({
                entry for candidate in pair_candidates.values() for entry in candidate["function_entries"]
            }),
            "evidence_class": "intervention_support" if supported else "correlation",
        })
    candidates.sort(key=lambda item: (
        item["evidence_class"] != "intervention_support",
        -item["support_repetition_count"], -abs(item["median_delta"]),
        item["normalized_address"], item["event_kind"],
    ))
    for rank, candidate in enumerate(candidates, 1):
        candidate["rank"] = rank

    output = {
        "format": REPORT_FORMAT,
        "collection_id": collection_id,
        "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        **identity,
        "intervention": intervention,
        "observation_window_sha256": observation_window_sha256,
        "required_repetitions": MIN_REPETITIONS,
        "comparison_ids": [report["comparison_id"] for report in reports],
        "comparison_report_sha256": [report["_report_sha256"] for report in reports],
        "sampling": {
            "comparison_count": len(reports),
            "complete_pair_count": complete_pairs,
            "all_complete": all_complete,
            "pairs": sampling,
        },
        "summary": {
            "candidate_count": len(candidates),
            "intervention_support_count": sum(item["evidence_class"] == "intervention_support" for item in candidates),
            "correlation_count": sum(item["evidence_class"] == "correlation" for item in candidates),
        },
        "ranked_candidates": candidates,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = output_path.with_name(output_path.name + ".tmp")
    temporary.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(output_path)
    return output


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = compare_files(args.manifest, args.output)
    except (InterventionError, OSError) as error:
        parser.exit(2, f"runtime intervention aggregation failed: {error}\n")
    print("comparisons:", report["sampling"]["comparison_count"])
    print("supported candidates:", report["summary"]["intervention_support_count"])
    print("output:", args.output.resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
