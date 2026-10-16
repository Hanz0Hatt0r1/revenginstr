"""Freeze a deterministic identity-disjoint portable P-code holdout.

The tool is deliberately project-neutral. Consumer repositories may provide:

- exclusion traces: identities already consumed by training/calibration;
- eligibility traces: identities allowed into this validation population.

This keeps title-specific origin/runtime filtering in the consumer while the core
owns deterministic selection, overlap removal and immutable provenance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from . import FROZEN_VALIDATION_FORMAT

CORPUS_FORMAT = "REVENGINSTR.PcodeCorpus/1"
DEFAULT_SELECTION_SALT = "revenginstr-frozen-v1"


def read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line_no, raw in enumerate(handle, 1):
            if not raw.strip():
                continue
            row = json.loads(raw)
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_no}: expected JSON object")
            yield row


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_jsonl(path: Path, rows: Iterable[dict[str, Any]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def identity_aliases(row: dict[str, Any]) -> set[str]:
    aliases: set[str] = set()
    record_id = row.get("id")
    if isinstance(record_id, str) and record_id:
        aliases.add("id:" + record_id)
    program = row.get("program")
    entry = row.get("source_entry")
    if isinstance(program, str) and program and isinstance(entry, str) and entry:
        aliases.add("pe:" + program + "\0" + entry)
    return aliases


def canonical_record_id(row: dict[str, Any]) -> str:
    record_id = row.get("id")
    if isinstance(record_id, str) and record_id:
        return record_id
    program = row.get("program")
    entry = row.get("source_entry")
    if isinstance(program, str) and program and isinstance(entry, str) and entry:
        return f"{program}:{entry}"
    raise ValueError("portable corpus row lacks id and program/source_entry identity")


def physical_identity(row: dict[str, Any]) -> str:
    program = row.get("program")
    entry = row.get("source_entry")
    if isinstance(program, str) and program and isinstance(entry, str) and entry:
        return program + "\0" + entry
    record_id = row.get("id")
    if isinstance(record_id, str) and record_id:
        return "id\0" + record_id
    raise ValueError("row has no stable identity")


def load_identity_aliases(paths: list[Path], *, role: str) -> set[str]:
    aliases: set[str] = set()
    for path in paths:
        for row in read_jsonl(path):
            row_aliases = identity_aliases(row)
            if not row_aliases:
                raise ValueError(f"{path}: {role} row has no id or program/source_entry")
            aliases.update(row_aliases)
    return aliases


def selection_key(row: dict[str, Any], salt: str) -> str:
    return hashlib.sha256((salt + "\0" + physical_identity(row)).encode("utf-8")).hexdigest()


def select_rows(
    corpus_path: Path,
    exclusion_paths: list[Path],
    *,
    eligibility_paths: list[Path] | None = None,
    limit: int,
    selection_salt: str = DEFAULT_SELECTION_SALT,
    include_external: bool = False,
) -> tuple[list[dict[str, Any]], Counter]:
    excluded = load_identity_aliases(exclusion_paths, role="exclusion")
    eligibility_paths = list(eligibility_paths or [])
    eligible_aliases = (
        load_identity_aliases(eligibility_paths, role="eligibility")
        if eligibility_paths
        else None
    )
    stats: Counter = Counter()
    candidates: list[tuple[str, dict[str, Any]]] = []
    seen_physical: set[str] = set()

    for row in read_jsonl(corpus_path):
        stats["input_rows"] += 1
        if row.get("format") != CORPUS_FORMAT:
            raise ValueError(f"unsupported corpus format: {row.get('format')!r}")
        if row.get("decompile_status") != "ok":
            stats["decompile_failed"] += 1
            continue
        if bool(row.get("external")) and not include_external:
            stats["external_removed"] += 1
            continue
        identity = physical_identity(row)
        if identity in seen_physical:
            stats["duplicate_identity"] += 1
            continue
        seen_physical.add(identity)
        aliases = identity_aliases(row)
        if eligible_aliases is not None and not aliases.intersection(eligible_aliases):
            stats["eligibility_removed"] += 1
            continue
        if aliases & excluded:
            stats["excluded_overlap"] += 1
            continue
        output = dict(row)
        output["id"] = canonical_record_id(row)
        candidates.append((selection_key(row, selection_salt), output))

    candidates.sort(key=lambda item: item[0])
    stats["eligible"] = len(candidates)
    selected = [row for _, row in candidates[:limit]]
    stats["selected"] = len(selected)
    return selected, stats


def _trace_manifest(paths: list[Path]) -> list[dict[str, str]]:
    return [{"path": str(path), "sha256": sha256_file(path)} for path in paths]


def freeze_validation(
    corpus_path: Path,
    output_dir: Path,
    *,
    exclude_traces: list[Path] | None = None,
    eligible_traces: list[Path] | None = None,
    limit: int = 500,
    tag: str = "frozen-validation",
    selection_salt: str = DEFAULT_SELECTION_SALT,
    include_external: bool = False,
    overwrite: bool = False,
) -> dict[str, Any]:
    if limit < 1:
        raise ValueError("limit must be >= 1")
    exclude_traces = list(exclude_traces or [])
    eligible_traces = list(eligible_traces or [])
    output_dir.mkdir(parents=True, exist_ok=True)
    corpus_out = output_dir / "corpus.jsonl"
    trace_out = output_dir / "trace.jsonl"
    manifest_out = output_dir / "manifest.json"
    if manifest_out.exists() and not overwrite:
        raise FileExistsError(
            f"frozen manifest already exists: {manifest_out}; pass overwrite=True to replace it"
        )

    selected, stats = select_rows(
        corpus_path,
        exclude_traces,
        eligibility_paths=eligible_traces,
        limit=limit,
        selection_salt=selection_salt,
        include_external=include_external,
    )
    if len(selected) != limit:
        raise ValueError(f"only {len(selected)} eligible rows available; need exactly {limit}")

    trace = [
        {
            "id": row["id"],
            "program": row.get("program"),
            "source_entry": row.get("source_entry"),
        }
        for row in selected
    ]
    write_jsonl(corpus_out, selected)
    write_jsonl(trace_out, trace)

    manifest = {
        "format": FROZEN_VALIDATION_FORMAT,
        "tag": tag,
        "selection": "stable_hash_identity_disjoint",
        "selection_salt": selection_salt,
        "limit": limit,
        "record_id_fallback": "program:source_entry",
        "include_external": include_external,
        "source_corpus": {
            "path": str(corpus_path),
            "sha256": sha256_file(corpus_path),
            "input_rows": int(stats["input_rows"]),
            "eligible": int(stats["eligible"]),
            "eligibility_removed": int(stats["eligibility_removed"]),
            "excluded_overlap": int(stats["excluded_overlap"]),
        },
        "eligibility_traces": _trace_manifest(eligible_traces),
        "exclusion_traces": _trace_manifest(exclude_traces),
        "frozen_corpus": {
            "path": str(corpus_out),
            "sha256": sha256_file(corpus_out),
            "rows": len(selected),
        },
        "trace": {
            "path": str(trace_out),
            "sha256": sha256_file(trace_out),
            "rows": len(trace),
        },
    }
    manifest_out.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return manifest


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--exclude-trace", type=Path, action="append", default=[])
    parser.add_argument("--eligible-trace", type=Path, action="append", default=[])
    parser.add_argument("--limit", type=int, default=500)
    parser.add_argument("--tag", default="frozen-validation")
    parser.add_argument("--selection-salt", default=DEFAULT_SELECTION_SALT)
    parser.add_argument("--include-external", action="store_true")
    parser.add_argument("--overwrite", action="store_true")
    args = parser.parse_args(argv)
    try:
        manifest = freeze_validation(
            args.corpus,
            args.output_dir,
            exclude_traces=args.exclude_trace,
            eligible_traces=args.eligible_trace,
            limit=args.limit,
            tag=args.tag,
            selection_salt=args.selection_salt,
            include_external=args.include_external,
            overwrite=args.overwrite,
        )
    except (ValueError, FileExistsError) as exc:
        raise SystemExit(str(exc)) from exc

    print("format:", manifest["format"])
    print("tag:", manifest["tag"])
    print("source rows:", manifest["source_corpus"]["input_rows"])
    print("eligibility removed:", manifest["source_corpus"]["eligibility_removed"])
    print("excluded overlap:", manifest["source_corpus"]["excluded_overlap"])
    print("eligible:", manifest["source_corpus"]["eligible"])
    print("frozen rows:", manifest["frozen_corpus"]["rows"])
    print("corpus sha256:", manifest["frozen_corpus"]["sha256"])
    print("corpus:", manifest["frozen_corpus"]["path"])
    print("trace:", manifest["trace"]["path"])
    print("manifest:", args.output_dir / "manifest.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
