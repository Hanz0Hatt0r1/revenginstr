"""Cluster methods with overlapping, provenance-linked structural features."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from collections import defaultdict
from pathlib import Path
from typing import Any

from revenginstr.family.features import jaccard
from revenginstr.family.mine import DisjointSet

FORMAT = "REVENGINSTR.ObjectRoleClusterAudit/1"
FEATURE_FORMAT = "REVENGINSTR.ObjectRoleFeatureSet/1"
FEATURE_GROUPS = ("receiver", "field", "vtable_slot", "callgraph", "effect_ir")
_SHA256 = set("0123456789abcdef")


def _digest(value: Any, where: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or set(value) - _SHA256:
        raise ValueError(f"{where}: invalid SHA-256")
    return value


def _read_jsonl(path: Path) -> tuple[str, list[dict[str, Any]]]:
    raw = path.read_bytes()
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ValueError(f"{path}: input must be UTF-8") from error
    rows = []
    for line_no, line in enumerate(lines, 1):
        if not line.strip():
            raise ValueError(f"{path}:{line_no}: blank JSONL record")
        try:
            row = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"{path}:{line_no}: invalid JSON") from error
        if not isinstance(row, dict):
            raise ValueError(f"{path}:{line_no}: expected an object")
        rows.append(row)
    return hashlib.sha256(raw).hexdigest(), rows


def _index_features(rows: list[dict[str, Any]]) -> tuple[str, dict[str, dict[str, set[str]]]]:
    if not rows:
        raise ValueError("object-role feature set must not be empty")
    program_id: str | None = None
    indexed: dict[str, dict[str, set[str]]] = {}
    for row_index, row in enumerate(rows, 1):
        where = f"feature-set row {row_index}"
        if set(row) != {"format", "program_id", "function_entry", "features"} or row.get("format") != FEATURE_FORMAT:
            raise ValueError(f"{where}: unexpected format or fields")
        current_program, function_entry, features = row["program_id"], row["function_entry"], row["features"]
        if not isinstance(current_program, str) or not current_program:
            raise ValueError(f"{where}: invalid program_id")
        if program_id is None:
            program_id = current_program
        elif program_id != current_program:
            raise ValueError("feature set contains multiple program ids")
        if not isinstance(function_entry, str) or not function_entry or function_entry in indexed:
            raise ValueError(f"{where}: invalid or duplicate function_entry")
        if not isinstance(features, list):
            raise ValueError(f"{where}: features must be an array")
        by_group: dict[str, set[str]] = defaultdict(set)
        for feature_index, feature in enumerate(features, 1):
            feature_where = f"{where} feature {feature_index}"
            if not isinstance(feature, dict) or set(feature) != {"group", "feature_sha256", "support"}:
                raise ValueError(f"{feature_where}: unexpected fields")
            group = feature["group"]
            if not isinstance(group, str) or group not in FEATURE_GROUPS:
                raise ValueError(f"{feature_where}: unsupported group")
            digest = _digest(feature["feature_sha256"], feature_where)
            support = feature["support"]
            if not isinstance(support, list) or not support:
                raise ValueError(f"{feature_where}: support must be a non-empty array")
            if digest in by_group[group]:
                raise ValueError(f"{feature_where}: duplicate group/feature")
            by_group[group].add(digest)
            seen_support = set()
            for support_index, source in enumerate(support, 1):
                source_where = f"{feature_where} support {support_index}"
                if not isinstance(source, dict) or set(source) != {"source_format", "source_sha256", "source_record_index"}:
                    raise ValueError(f"{source_where}: unexpected fields")
                if not isinstance(source["source_format"], str) or not source["source_format"]:
                    raise ValueError(f"{source_where}: invalid source_format")
                _digest(source["source_sha256"], source_where)
                source_record_index = source["source_record_index"]
                if isinstance(source_record_index, bool) or not isinstance(source_record_index, int) or source_record_index < 1:
                    raise ValueError(f"{source_where}: invalid source_record_index")
                identity = (source["source_format"], source["source_sha256"], source_record_index)
                if identity in seen_support:
                    raise ValueError(f"{source_where}: duplicate provenance")
                seen_support.add(identity)
        indexed[function_entry] = by_group
    return program_id or "", indexed


def cluster_object_role_candidates(
    rows: list[dict[str, Any]],
    *,
    feature_set_sha256: str,
    similarity_threshold: float = 0.5,
    min_shared_groups: int = 2,
    max_candidate_pairs: int = 100_000,
) -> dict[str, Any]:
    """Return similarity edges and connected components, without role labels."""
    _digest(feature_set_sha256, "feature set")
    if isinstance(similarity_threshold, bool) or not isinstance(similarity_threshold, (int, float)) or not math.isfinite(similarity_threshold) or not 0 < similarity_threshold <= 1:
        raise ValueError("similarity_threshold must be finite and in (0, 1]")
    if isinstance(min_shared_groups, bool) or not isinstance(min_shared_groups, int) or not 1 <= min_shared_groups <= len(FEATURE_GROUPS):
        raise ValueError("min_shared_groups must be between 1 and 5")
    if isinstance(max_candidate_pairs, bool) or not isinstance(max_candidate_pairs, int) or max_candidate_pairs < 1:
        raise ValueError("max_candidate_pairs must be positive")

    program_id, functions = _index_features(rows)
    entries = sorted(functions)
    entry_indices = {entry: index for index, entry in enumerate(entries)}
    inverted: dict[tuple[str, str], list[int]] = defaultdict(list)
    for function_index, entry in enumerate(entries):
        for group, features in functions[entry].items():
            for feature in features:
                inverted[(group, feature)].append(function_index)

    candidate_pairs: set[tuple[int, int]] = set()
    for members in inverted.values():
        for position, left in enumerate(members):
            for right in members[position + 1:]:
                candidate_pairs.add((left, right))
                if len(candidate_pairs) > max_candidate_pairs:
                    raise ValueError(f"object-role candidate-pair budget exceeded: {max_candidate_pairs}")

    pairs = []
    for left_index, right_index in sorted(candidate_pairs):
        left_entry, right_entry = entries[left_index], entries[right_index]
        group_scores: dict[str, float] = {}
        shared_groups = []
        shared_features = []
        for group in FEATURE_GROUPS:
            left_features = functions[left_entry].get(group, set())
            right_features = functions[right_entry].get(group, set())
            if left_features and right_features:
                group_scores[group] = jaccard(frozenset(left_features), frozenset(right_features))
            shared = left_features & right_features
            if shared:
                shared_groups.append(group)
                shared_features.extend({"group": group, "feature_sha256": value} for value in sorted(shared))
        if len(shared_groups) < min_shared_groups or not group_scores:
            continue
        similarity = sum(group_scores.values()) / len(group_scores)
        if similarity < similarity_threshold:
            continue
        pair_id = hashlib.sha256(
            f"{feature_set_sha256}\0{left_entry}\0{right_entry}".encode("utf-8")
        ).hexdigest()
        pairs.append({
            "pair_id": pair_id,
            "left_function_entry": left_entry,
            "right_function_entry": right_entry,
            "similarity": similarity,
            "group_scores": group_scores,
            "shared_groups": shared_groups,
            "shared_features": shared_features,
        })

    components = DisjointSet(len(entries))
    for pair in pairs:
        components.union(entry_indices[pair["left_function_entry"]], entry_indices[pair["right_function_entry"]])
    pairs_by_root: dict[int, list[str]] = defaultdict(list)
    for pair in pairs:
        root = components.find(entry_indices[pair["left_function_entry"]])
        pairs_by_root[root].append(pair["pair_id"])
    member_groups: dict[int, list[str]] = defaultdict(list)
    for index, entry in enumerate(entries):
        member_groups[components.find(index)].append(entry)
    clusters = []
    for members in member_groups.values():
        if len(members) < 2:
            continue
        cluster_id = hashlib.sha256("\0".join([feature_set_sha256, *members]).encode("utf-8")).hexdigest()
        clusters.append({
            "cluster_id": cluster_id,
            "member_function_entries": members,
            "pair_ids": sorted(pairs_by_root[components.find(entry_indices[members[0]])]),
        })
    clusters.sort(key=lambda row: row["member_function_entries"])

    return {
        "format": FORMAT,
        "program_id": program_id,
        "claim_scope": "Similarity candidates only; no semantic role, class label, inheritance, or object identity is inferred.",
        "config": {
            "similarity_threshold": similarity_threshold,
            "min_shared_groups": min_shared_groups,
            "max_candidate_pairs": max_candidate_pairs,
        },
        "source": {
            "feature_set_sha256": feature_set_sha256,
            "function_count": len(functions),
            "feature_count": sum(len(group) for features in functions.values() for group in features.values()),
            "candidate_pairs_considered": len(candidate_pairs),
            "candidate_pair_count": len(pairs),
            "cluster_count": len(clusters),
        },
        "candidate_pairs": pairs,
        "clusters": clusters,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("feature_set_jsonl", type=Path)
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--min-shared-groups", type=int, default=2)
    parser.add_argument("--max-candidate-pairs", type=int, default=100_000)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    feature_set_sha256, rows = _read_jsonl(args.feature_set_jsonl)
    report = cluster_object_role_candidates(
        rows,
        feature_set_sha256=feature_set_sha256,
        similarity_threshold=args.threshold,
        min_shared_groups=args.min_shared_groups,
        max_candidate_pairs=args.max_candidate_pairs,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("functions:", report["source"]["function_count"])
    print("candidate pairs:", report["source"]["candidate_pair_count"])
    print("clusters:", report["source"]["cluster_count"])
    print("output:", args.output)
    return 0
