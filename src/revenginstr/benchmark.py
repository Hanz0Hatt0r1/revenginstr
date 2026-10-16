"""Run a pinned, project-neutral reverse-engineering benchmark manifest."""
from __future__ import annotations

import argparse
import csv
import hashlib
import importlib
import json
import math
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

from . import __version__

MANIFEST_FORMAT = "REVENGINSTR.BenchmarkManifest/1"
SUMMARY_FORMAT = "REVENGINSTR.BenchmarkSummary/1"
TOOLS = {
    "pcode-audit": ("revenginstr.pcode.audit", "main"),
    "foreign-guard": ("revenginstr.ood.foreign_guard", "main"),
    "callgraph": ("revenginstr.evidence.callgraph", "main"),
    "evidence-aggregate": ("revenginstr.evidence.aggregate", "main"),
    "receiver-plan": ("revenginstr.receiver.plan", "main"),
    "receiver-infer": ("revenginstr.receiver.infer", "main"),
    "family-mine": ("revenginstr.family.mine", "main"),
    "selective-train": ("revenginstr.ml.selective", "train_main"),
    "selective-infer": ("revenginstr.ml.selective", "infer_main"),
    "evidence-selective-train": ("revenginstr.ml.evidence_selective", "train_main"),
    "evidence-selective-infer": ("revenginstr.ml.evidence_selective", "infer_main"),
    "accept-router-train": ("revenginstr.ml.accept_error_router", "train_main"),
    "accept-router-infer": ("revenginstr.ml.accept_error_router", "infer_main"),
    "freeze-validation": ("revenginstr.validation.frozen", "main"),
    "drift-audit": ("revenginstr.validation.drift", "main"),
}
_ARTIFACT_TOKEN = re.compile(r"\$\{artifact:([A-Za-z0-9][A-Za-z0-9_.-]*)\}")


class BenchmarkError(ValueError):
    """A manifest or benchmark artifact violates its declared contract."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_path(path: Path) -> str:
    if path.is_file():
        return sha256_file(path)
    if not path.is_dir():
        raise BenchmarkError(f"artifact does not exist: {path}")
    digest = hashlib.sha256()
    for child in sorted(path.rglob("*")):
        if child.is_symlink():
            raise BenchmarkError(f"directory artifact contains a symlink: {child}")
        if child.is_file():
            relative = child.relative_to(path).as_posix().encode("utf-8")
            digest.update(len(relative).to_bytes(8, "big"))
            digest.update(relative)
            digest.update(bytes.fromhex(sha256_file(child)))
    return digest.hexdigest()


def _schema_directory() -> Path:
    source_tree = Path(__file__).resolve().parents[2] / "schemas"
    if source_tree.is_dir():
        return source_tree
    installed = Path(sys.prefix) / "share" / "revenginstr" / "schemas"
    return installed


def _jsonschema():
    try:
        from jsonschema import Draft202012Validator
    except ImportError as exc:
        raise BenchmarkError(
            "benchmark schema validation requires jsonschema; install revenginstr[benchmark]"
        ) from exc
    return Draft202012Validator


def _validate_manifest_schema(manifest: dict[str, Any]) -> None:
    Draft202012Validator = _jsonschema()
    schema_path = _schema_directory() / "benchmark-manifest-v1.schema.json"
    if not schema_path.is_file():
        raise BenchmarkError(f"benchmark manifest schema is missing: {schema_path}")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    errors = sorted(Draft202012Validator(schema).iter_errors(manifest), key=lambda item: tuple(map(str, item.absolute_path)))
    if errors:
        first = errors[0]
        location = "/".join(str(part) for part in first.absolute_path) or "<root>"
        raise BenchmarkError(f"manifest {location}: {first.message}")


def _load_schema_contracts(manifest: dict[str, Any], base: Path) -> dict[str, tuple[str, Any]]:
    Draft202012Validator = _jsonschema()
    contracts: dict[str, tuple[str, Any]] = {}
    for schema_id, contract in manifest.get("schemas", {}).items():
        path = _resolve_path(base, contract["path"])
        if not path.is_file():
            raise BenchmarkError(f"schema {schema_id!r} does not exist: {path}")
        actual_hash = sha256_file(path)
        if actual_hash != contract["sha256"].lower():
            raise BenchmarkError(f"schema {schema_id!r} SHA-256 mismatch: expected {contract['sha256']}, got {actual_hash}")
        try:
            schema = json.loads(path.read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schema)
        except Exception as exc:
            raise BenchmarkError(f"schema {schema_id!r} is invalid: {exc}") from exc
        contracts[schema_id] = (contract["version"], schema)
    return contracts


def _resolve_path(base: Path, value: str) -> Path:
    path = Path(value).expanduser()
    return path.resolve() if path.is_absolute() else (base / path).resolve()


def _validate_value(value: Any, validator: Any, *, where: str, expected_format: str | None) -> None:
    if expected_format is not None:
        if not isinstance(value, dict) or value.get("format") != expected_format:
            actual = value.get("format") if isinstance(value, dict) else None
            raise BenchmarkError(f"{where}: expected format {expected_format!r}, got {actual!r}")
    if validator is not None:
        errors = list(validator.iter_errors(value))
        if errors:
            error = errors[0]
            location = "/".join(str(part) for part in error.absolute_path) or "<root>"
            raise BenchmarkError(f"{where} schema {location}: {error.message}")


def _validate_artifact(path: Path, artifact: dict[str, Any], schemas: dict[str, tuple[str, Any]]) -> str:
    kind = artifact["kind"]
    if kind == "directory":
        if not path.is_dir():
            raise BenchmarkError(f"expected directory artifact: {path}")
        return sha256_path(path)
    if not path.is_file():
        raise BenchmarkError(f"expected file artifact: {path}")

    schema_id = artifact.get("schema")
    validator = None
    if schema_id is not None:
        if schema_id not in schemas:
            raise BenchmarkError(f"artifact references unknown schema {schema_id!r}")
        validator = _jsonschema()(schemas[schema_id][1])
    expected_format = artifact.get("format")
    content = artifact["content"]
    if content == "json":
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BenchmarkError(f"invalid JSON artifact {path}: {exc}") from exc
        _validate_value(value, validator, where=str(path), expected_format=expected_format)
    elif content == "jsonl":
        count = 0
        with path.open("r", encoding="utf-8") as handle:
            for line_no, line in enumerate(handle, 1):
                if not line.strip():
                    continue
                try:
                    value = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise BenchmarkError(f"{path}:{line_no}: invalid JSON: {exc}") from exc
                _validate_value(value, validator, where=f"{path}:{line_no}", expected_format=expected_format)
                count += 1
        if count == 0:
            raise BenchmarkError(f"JSONL artifact is empty: {path}")
    elif content in {"csv", "tsv"}:
        delimiter = "," if content == "csv" else "\t"
        with path.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle, delimiter=delimiter)
            if not reader.fieldnames:
                raise BenchmarkError(f"delimited artifact has no header: {path}")
            for line_no, value in enumerate(reader, 2):
                _validate_value(value, validator, where=f"{path}:{line_no}", expected_format=expected_format)
    elif validator is not None or expected_format is not None:
        raise BenchmarkError(f"binary artifact cannot declare a JSON schema or format: {path}")
    return sha256_file(path)


def _stage_plan(manifest: dict[str, Any], mode: str) -> tuple[list[dict[str, Any]], dict[str, str]]:
    if mode not in {"smoke", "full"}:
        raise BenchmarkError(f"unsupported benchmark mode: {mode!r}")
    artifacts = manifest["artifacts"]
    stages = manifest["stages"]
    stage_ids: set[str] = set()
    producers: dict[str, str] = {}
    selected = [stage for stage in stages if stage.get("mode", "both") in {"both", mode}]
    selected_ids = {stage["id"] for stage in selected}

    for artifact_id, artifact in artifacts.items():
        if artifact["role"] not in {"input", "output"}:
            raise BenchmarkError(f"artifact {artifact_id!r} has invalid role")
        schema_id = artifact.get("schema")
        if schema_id is not None and schema_id not in manifest.get("schemas", {}):
            raise BenchmarkError(f"artifact {artifact_id!r} references unknown schema {schema_id!r}")
    for stage in stages:
        stage_id = stage["id"]
        if stage_id in stage_ids:
            raise BenchmarkError(f"duplicate stage id: {stage_id}")
        stage_ids.add(stage_id)
        for dependency in stage.get("depends_on", []):
            if dependency not in stage_ids:
                raise BenchmarkError(f"stage {stage_id!r} dependency {dependency!r} must appear earlier")
        for artifact_id in stage.get("inputs", []):
            if artifact_id not in artifacts:
                raise BenchmarkError(f"stage {stage_id!r} references unknown input artifact {artifact_id!r}")
        for artifact_id in stage.get("outputs", []):
            if artifact_id not in artifacts:
                raise BenchmarkError(f"stage {stage_id!r} references unknown output artifact {artifact_id!r}")
            if artifacts[artifact_id]["role"] != "output":
                raise BenchmarkError(f"stage {stage_id!r} output {artifact_id!r} is not declared as an output artifact")
            if artifact_id in producers:
                raise BenchmarkError(f"output artifact {artifact_id!r} has multiple producers")
            producers[artifact_id] = stage_id

        references: set[str] = set()
        for argument in stage.get("args", []):
            match = _ARTIFACT_TOKEN.fullmatch(argument)
            if match:
                references.add(match.group(1))
            elif "${artifact:" in argument:
                raise BenchmarkError(f"stage {stage_id!r} has a malformed artifact placeholder: {argument!r}")
        declared = set(stage.get("inputs", [])) | set(stage.get("outputs", []))
        if references != declared:
            raise BenchmarkError(
                f"stage {stage_id!r} artifact arguments {sorted(references)} do not match declared inputs/outputs {sorted(declared)}"
            )

    for artifact_id, artifact in artifacts.items():
        if artifact["role"] == "output" and artifact_id not in producers:
            raise BenchmarkError(f"output artifact {artifact_id!r} has no producing stage")

    for stage in selected:
        for dependency in stage.get("depends_on", []):
            if dependency not in selected_ids:
                raise BenchmarkError(f"stage {stage['id']!r} depends on {dependency!r}, which is excluded in {mode} mode")
        by_id = {item["id"]: item for item in stages}
        ancestors: set[str] = set()

        def add_ancestors(dependency: str) -> None:
            if dependency in ancestors:
                return
            ancestors.add(dependency)
            for parent in by_id[dependency].get("depends_on", []):
                add_ancestors(parent)

        for dependency in stage.get("depends_on", []):
            add_ancestors(dependency)
        for artifact_id in stage.get("inputs", []):
            producer = producers.get(artifact_id)
            if producer is not None and producer not in ancestors:
                raise BenchmarkError(f"stage {stage['id']!r} must depend on producer {producer!r} of {artifact_id!r}")

    benchmark = manifest["benchmark"]
    if benchmark["dataset_artifact"] not in artifacts:
        raise BenchmarkError("benchmark dataset_artifact is not declared")
    if artifacts[benchmark["dataset_artifact"]]["role"] != "input":
        raise BenchmarkError("benchmark dataset_artifact must be an input")
    family_artifact = benchmark.get("family_artifact")
    if family_artifact is not None and family_artifact not in artifacts:
        raise BenchmarkError("benchmark family_artifact is not declared")
    if family_artifact is not None and artifacts[family_artifact]["role"] != "input":
        raise BenchmarkError("benchmark family_artifact must be an input")
    for metric in manifest.get("metrics", []):
        if metric["artifact"] not in artifacts:
            raise BenchmarkError(f"metric {metric['name']!r} references unknown artifact {metric['artifact']!r}")
        if "minimum" in metric and "maximum" in metric and metric["minimum"] > metric["maximum"]:
            raise BenchmarkError(f"metric {metric['name']!r} has minimum greater than maximum")
    return selected, producers


def _expand_args(stage: dict[str, Any], paths: dict[str, Path]) -> list[str]:
    expanded: list[str] = []
    for argument in stage.get("args", []):
        match = _ARTIFACT_TOKEN.fullmatch(argument)
        if match:
            artifact_id = match.group(1)
            if artifact_id not in paths:
                raise BenchmarkError(f"stage {stage['id']!r} references unknown artifact {artifact_id!r}")
            expanded.append(str(paths[artifact_id]))
        else:
            expanded.append(argument)
    return expanded


def _pointer_value(document: Any, pointer: str) -> Any:
    if pointer == "":
        return document
    if not pointer.startswith("/"):
        raise BenchmarkError(f"JSON Pointer must be empty or start with '/': {pointer!r}")
    value = document
    for raw_part in pointer[1:].split("/"):
        if re.search(r"~(?![01])", raw_part):
            raise BenchmarkError(f"invalid JSON Pointer escape in {pointer!r}")
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(value, list):
            if not part.isdigit() or (len(part) > 1 and part.startswith("0")):
                raise BenchmarkError(f"invalid list index {part!r} in JSON Pointer {pointer!r}")
            value = value[int(part)]
        elif isinstance(value, dict):
            value = value[part]
        else:
            raise BenchmarkError(f"JSON Pointer {pointer!r} traverses a scalar")
    return value


def _evaluate_metrics(manifest: dict[str, Any], paths: dict[str, Path], mode: str) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for metric in manifest.get("metrics", []):
        if metric.get("mode", "both") not in {"both", mode}:
            continue
        item = {key: metric[key] for key in ("name", "artifact", "json_pointer", "minimum", "maximum") if key in metric}
        try:
            artifact_id = metric["artifact"]
            artifact = manifest["artifacts"][artifact_id]
            path = paths[artifact_id]
            if artifact["kind"] != "file" or artifact["content"] != "json":
                raise BenchmarkError("metric source must be a JSON file artifact")
            document = json.loads(path.read_text(encoding="utf-8"))
            value = _pointer_value(document, metric["json_pointer"])
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(float(value)):
                raise BenchmarkError(f"metric value is not a finite number: {value!r}")
            passed = (("minimum" not in metric or value >= metric["minimum"])
                      and ("maximum" not in metric or value <= metric["maximum"]))
            item.update({"value": value, "passed": passed})
        except (OSError, KeyError, IndexError, json.JSONDecodeError, BenchmarkError) as exc:
            item.update({"value": None, "passed": False, "error": str(exc)})
        results.append(item)
    return results


def _tool_version() -> str:
    return __version__


def _write_summary(path: Path, summary: dict[str, Any]) -> None:
    Draft202012Validator = _jsonschema()
    schema_path = _schema_directory() / "benchmark-summary-v1.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    errors = list(Draft202012Validator(schema).iter_errors(summary))
    if errors:
        raise BenchmarkError(f"generated summary is invalid: {errors[0].message}")
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def run_benchmark(manifest_path: Path, *, mode: str = "full", output_path: Path | None = None) -> tuple[dict[str, Any], int]:
    manifest_path = manifest_path.resolve()
    base = manifest_path.parent
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(manifest, dict):
        raise BenchmarkError("manifest root must be a JSON object")
    _validate_manifest_schema(manifest)
    schemas = _load_schema_contracts(manifest, base)
    stages, _ = _stage_plan(manifest, mode)
    artifacts = manifest["artifacts"]
    paths = {artifact_id: _resolve_path(base, artifact["path"]) for artifact_id, artifact in artifacts.items()}
    inputs = {artifact_id for stage in stages for artifact_id in stage.get("inputs", [])
              if artifacts[artifact_id]["role"] == "input"}
    inputs.add(manifest["benchmark"]["dataset_artifact"])
    family_artifact = manifest["benchmark"].get("family_artifact")
    if family_artifact is not None:
        inputs.add(family_artifact)
    for metric in manifest.get("metrics", []):
        if metric.get("mode", "both") in {"both", mode} and artifacts[metric["artifact"]]["role"] == "input":
            inputs.add(metric["artifact"])
    outputs = {artifact_id for stage in stages for artifact_id in stage.get("outputs", [])}

    artifact_reports: dict[str, Any] = {}
    for artifact_id in sorted(inputs):
        artifact = artifacts[artifact_id]
        actual_hash = _validate_artifact(paths[artifact_id], artifact, schemas)
        if actual_hash != artifact["sha256"].lower():
            raise BenchmarkError(f"artifact {artifact_id!r} SHA-256 mismatch: expected {artifact['sha256']}, got {actual_hash}")
        artifact_reports[artifact_id] = {
            "path": artifact["path"], "kind": artifact["kind"],
            "format": artifact.get("format"), "sha256": actual_hash, "pinned": True,
        }
    for artifact_id in outputs:
        if paths[artifact_id].exists():
            raise BenchmarkError(f"output artifact already exists: {paths[artifact_id]}")

    result_path = output_path or (base / "benchmark-summary.json")
    if not result_path.is_absolute():
        result_path = (base / result_path).resolve()
    for artifact_path in paths.values():
        if result_path == artifact_path or result_path in artifact_path.parents or artifact_path in result_path.parents:
            raise BenchmarkError(f"summary path overlaps a declared artifact: {result_path}")
    actual_tool_version = _tool_version()
    if actual_tool_version != manifest["toolchain"]["revenginstr_version"]:
        raise BenchmarkError(
            f"revenginstr version mismatch: manifest pins {manifest['toolchain']['revenginstr_version']!r}, "
            f"running {_tool_version()!r}"
        )
    config_identity = {
        "configs": manifest.get("configs", {}),
        "stages": [{key: stage[key] for key in (
            "id", "tool", "mode", "args", "inputs", "outputs", "depends_on", "timeout_seconds",
        ) if key in stage} for stage in manifest["stages"]],
    }
    config_hash = hashlib.sha256(
        json.dumps(config_identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    summary: dict[str, Any] = {
        "format": SUMMARY_FORMAT,
        "benchmark": dict(manifest["benchmark"]),
        "mode": mode,
        "manifest_sha256": sha256_file(manifest_path),
        "tool_version": actual_tool_version,
        "toolchain": manifest["toolchain"],
        "schema_versions": {key: value["version"] for key, value in sorted(manifest.get("schemas", {}).items())},
        "configuration_sha256": config_hash,
        "status": "passed",
        "artifacts": artifact_reports,
        "stages": [],
        "metrics": [],
        "gate_failures": [],
    }

    source_path = str(Path(__file__).resolve().parents[1])
    inherited_pythonpath = os.environ.get("PYTHONPATH")
    pythonpath = source_path if not inherited_pythonpath else source_path + os.pathsep + inherited_pythonpath
    child_env = {**os.environ, "PYTHONPATH": pythonpath}

    for stage in stages:
        args = _expand_args(stage, paths)
        command = [sys.executable, "-m", "revenginstr.benchmark", "_stage", stage["tool"], *args]
        print(f"[{stage['id']}] {stage['tool']}", flush=True)
        started = time.perf_counter()
        stage_result: dict[str, Any] = {
            "id": stage["id"], "tool": stage["tool"], "command": command,
            "status": "passed", "exit_code": None,
        }
        try:
            process = subprocess.run(
                command, cwd=Path(__file__).resolve().parents[2], env=child_env,
                timeout=stage.get("timeout_seconds"), check=False,
            )
            stage_result["exit_code"] = process.returncode
            if process.returncode != 0:
                stage_result["status"] = "failed"
                stage_result["error"] = f"tool exited with status {process.returncode}"
                summary["status"] = "failed"
            else:
                for artifact_id in stage.get("outputs", []):
                    artifact = artifacts[artifact_id]
                    actual_hash = _validate_artifact(paths[artifact_id], artifact, schemas)
                    artifact_reports[artifact_id] = {
                        "path": artifact["path"], "kind": artifact["kind"],
                        "format": artifact.get("format"), "sha256": actual_hash, "pinned": False,
                    }
        except subprocess.TimeoutExpired:
            stage_result["status"] = "timed_out"
            stage_result["error"] = f"stage exceeded {stage['timeout_seconds']} seconds"
            summary["status"] = "failed"
        except BenchmarkError as exc:
            stage_result["status"] = "artifact_validation_failed"
            stage_result["error"] = str(exc)
            summary["status"] = "failed"
        finally:
            stage_result["duration_seconds"] = round(time.perf_counter() - started, 6)
        summary["stages"].append(stage_result)
        if summary["status"] == "failed":
            break

    if summary["status"] == "passed":
        summary["metrics"] = _evaluate_metrics(manifest, paths, mode)
        summary["gate_failures"] = [metric["name"] for metric in summary["metrics"] if not metric["passed"]]
        if summary["gate_failures"]:
            summary["status"] = "failed_gates"
    summary["artifacts"] = artifact_reports
    _write_summary(result_path, summary)
    return summary, 0 if summary["status"] == "passed" else 2


def _run_tool(tool: str, argv: list[str]) -> int:
    if tool not in TOOLS:
        raise BenchmarkError(f"unsupported benchmark tool: {tool!r}")
    module_name, function_name = TOOLS[tool]
    function = getattr(importlib.import_module(module_name), function_name)
    return int(function(argv) or 0)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "_stage":
        if len(argv) < 2:
            raise SystemExit("missing benchmark stage tool")
        try:
            return _run_tool(argv[1], argv[2:])
        except BenchmarkError as exc:
            raise SystemExit(str(exc)) from exc

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--mode", choices=("smoke", "full"), default="full")
    parser.add_argument("--output", type=Path, help="summary JSON path (default: benchmark-summary.json beside the manifest)")
    args = parser.parse_args(argv)
    try:
        summary, code = run_benchmark(args.manifest, mode=args.mode, output_path=args.output)
    except (BenchmarkError, OSError, json.JSONDecodeError) as exc:
        parser.exit(2, f"benchmark failed: {exc}\n")
    print(f"benchmark status: {summary['status']}")
    print(f"summary: {(args.output or args.manifest.parent / 'benchmark-summary.json').resolve()}")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
