"""Rerun a pinned benchmark and compare its deterministic outputs."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

from .benchmark import (
    BenchmarkError,
    _resolve_path,
    _validate_manifest_schema,
    run_benchmark,
)
from . import __version__

FORMAT = "REVENGINSTR.DeterminismAudit/1"
_IGNORED_STAGE_FIELDS = {"duration_seconds", "peak_rss_bytes"}


def _hash_json(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _isolated_manifest(manifest: dict[str, Any], base: Path, output_root: Path) -> dict[str, Any]:
    isolated = copy.deepcopy(manifest)
    for contract in isolated.get("schemas", {}).values():
        contract["path"] = str(_resolve_path(base, contract["path"]))
    for artifact_id, artifact in isolated["artifacts"].items():
        if artifact["role"] == "input":
            artifact["path"] = str(_resolve_path(base, artifact["path"]))
        else:
            suffix = Path(artifact["path"]).suffix if artifact["kind"] == "file" else ""
            output_name = f"output{suffix}" if artifact["kind"] == "file" else "directory"
            artifact["path"] = str(output_root / artifact_id / output_name)
    return isolated


def _stable_summary(summary: dict[str, Any]) -> dict[str, Any]:
    stable = copy.deepcopy(summary)
    for stage in stable.get("stages", []):
        for field in _IGNORED_STAGE_FIELDS:
            stage.pop(field, None)
    return stable


def _difference_paths(left: Any, right: Any, prefix: str = "") -> list[str]:
    if isinstance(left, dict) and isinstance(right, dict):
        differences = []
        for key in sorted(set(left) | set(right)):
            escaped = str(key).replace("~", "~0").replace("/", "~1")
            pointer = f"{prefix}/{escaped}"
            if key not in left or key not in right:
                differences.append(pointer)
            else:
                differences.extend(_difference_paths(left[key], right[key], pointer))
        return differences
    if isinstance(left, list) and isinstance(right, list):
        differences = []
        if len(left) != len(right):
            differences.append(f"{prefix}/length")
        for index, (first, second) in enumerate(zip(left, right)):
            differences.extend(_difference_paths(first, second, f"{prefix}/{index}"))
        return differences
    return [] if type(left) is type(right) and left == right else [prefix or "/"]


def _run_record(summary: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": summary["status"],
        "manifest_sha256": summary["manifest_sha256"],
        "configuration_sha256": summary["configuration_sha256"],
        "artifact_sha256": {
            key: value["sha256"] for key, value in sorted(summary["artifacts"].items())
        },
        "metrics_sha256": _hash_json(summary["metrics"]),
        "projections_sha256": _hash_json(summary.get("projections", [])),
        "stage_results": [
            {key: stage[key] for key in ("id", "tool", "status", "exit_code") if key in stage}
            for stage in summary["stages"]
        ],
    }


def _remove_outputs(manifest: dict[str, Any], base: Path) -> None:
    for artifact in manifest["artifacts"].values():
        if artifact["role"] != "output":
            continue
        path = _resolve_path(base, artifact["path"])
        if path.is_dir():
            shutil.rmtree(path)
        elif path.exists():
            path.unlink()


def audit_determinism(
    manifest_path: Path,
    *,
    mode: str = "full",
    output_path: Path,
) -> tuple[dict[str, Any], int]:
    manifest_path = manifest_path.resolve()
    base = manifest_path.parent
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise BenchmarkError("manifest root must be a JSON object")
    _validate_manifest_schema(manifest)

    output_path = output_path.resolve()
    if output_path == manifest_path:
        raise BenchmarkError("determinism report path cannot overwrite the manifest")
    protected_paths = [manifest_path]
    protected_paths.extend(_resolve_path(base, artifact["path"]) for artifact in manifest["artifacts"].values())
    protected_paths.extend(_resolve_path(base, contract["path"]) for contract in manifest.get("schemas", {}).values())
    for artifact_path in protected_paths:
        if output_path == artifact_path or output_path in artifact_path.parents or artifact_path in output_path.parents:
            raise BenchmarkError(f"determinism report path overlaps a benchmark artifact: {output_path}")

    summaries: list[dict[str, Any]] = []
    error: str | None = None
    with tempfile.TemporaryDirectory(prefix="revenginstr-determinism-") as temporary:
        root = Path(temporary)
        run_root = root / "outputs"
        run_root.mkdir()
        replay_manifest = _isolated_manifest(manifest, base, run_root)
        replay_path = root / "benchmark.json"
        replay_path.write_text(json.dumps(replay_manifest, sort_keys=True) + "\n", encoding="utf-8")
        summary_path = root / "benchmark-summary.json"
        for run_number in (1, 2):
            try:
                summary, _code = run_benchmark(replay_path, mode=mode, output_path=summary_path)
                summaries.append(summary)
                if summary["status"] not in {"passed", "failed_gates"}:
                    error = f"benchmark run {run_number} did not complete successfully"
                    break
            except (BenchmarkError, OSError, json.JSONDecodeError) as exc:
                error = f"benchmark run {run_number} failed: {exc}"
                break
            if run_number == 1:
                _remove_outputs(replay_manifest, replay_path.parent)

    differences: list[str] = []
    if error is None and len(summaries) == 2:
        differences = _difference_paths(_stable_summary(summaries[0]), _stable_summary(summaries[1]))
    deterministic = error is None and len(summaries) == 2 and not differences
    report: dict[str, Any] = {
        "format": FORMAT,
        "benchmark_id": manifest["benchmark"]["id"],
        "mode": mode,
        "tool_version": __version__,
        "status": "deterministic" if deterministic else "nondeterministic" if error is None else "failed",
        "deterministic": deterministic,
        "difference_paths": differences,
        "ignored_fields": ["stages[*].duration_seconds", "stages[*].peak_rss_bytes"],
        "runs": [_run_record(summary) for summary in summaries],
    }
    if error is not None:
        report["error"] = error
    _write_report(output_path, report)
    return report, 0 if deterministic else 2


def _write_report(path: Path, report: dict[str, Any]) -> None:
    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:
        raise BenchmarkError("determinism audit schema validation requires jsonschema; install revenginstr[benchmark]") from exc
    schema_path = Path(__file__).resolve().parents[2] / "schemas" / "determinism-audit-v1.schema.json"
    if not schema_path.is_file():
        schema_path = Path(sys.prefix) / "share" / "revenginstr" / "schemas" / schema_path.name
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    errors = list(Draft202012Validator(schema).iter_errors(report))
    if errors:
        raise BenchmarkError(f"generated determinism report is invalid: {errors[0].message}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--mode", choices=("smoke", "full"), default="full")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report, code = audit_determinism(args.manifest, mode=args.mode, output_path=args.output)
    except (BenchmarkError, OSError, json.JSONDecodeError) as exc:
        parser.exit(2, f"determinism audit failed: {exc}\n")
    print(f"determinism status: {report['status']}")
    print(f"report: {args.output.resolve()}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
