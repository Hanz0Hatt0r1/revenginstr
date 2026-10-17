#!/usr/bin/env python3
"""Compile lowerable functions from a hash-pinned P-code corpus into object shards."""
from __future__ import annotations

import argparse
import collections
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

from revenginstr.pcode.c_lowering import (
    CORPUS_FORMAT,
    MANIFEST_FORMAT,
    SPACES_FORMAT,
    _RUNTIME,
    _json_object,
    _open_text,
    _sha256,
    compile_function,
    PcodeLoweringError,
)

FORMAT = "REVENGINSTR.PcodeCFunctionShardBuild/1"
STATE_FORMAT = "REVENGINSTR.PcodeCFunctionShardBuildState/2"


def _rejection_reason(error: PcodeLoweringError) -> str:
    message = str(error)
    _, separator, reason = message.partition(": ")
    if not separator:
        reason = message
    return re.sub(r"0x[0-9a-fA-F]+", "0x<offset>", reason)


def build(
    corpus_path: Path,
    manifest_path: Path,
    spaces_path: Path,
    output_dir: Path,
    compiler: str,
    *,
    shard_size: int = 500,
    jobs: int = 4,
    compiler_args: tuple[str, ...] = (),
    resume: bool = False,
) -> dict:
    manifest = _json_object(manifest_path)
    spaces = _json_object(spaces_path)
    if manifest.get("format") != MANIFEST_FORMAT:
        raise ValueError(f"{manifest_path}: expected {MANIFEST_FORMAT}")
    if spaces.get("format") != SPACES_FORMAT:
        raise ValueError(f"{spaces_path}: expected {SPACES_FORMAT}")
    corpus_sha256 = _sha256(corpus_path)
    if manifest.get("output_sha256") != corpus_sha256:
        raise ValueError("corpus manifest SHA-256 does not match the instruction corpus")
    program = manifest.get("program")
    language_id = manifest.get("language_id")
    if (not isinstance(program, str) or not program or not isinstance(language_id, str) or
            not language_id or spaces.get("language_id") != language_id):
        raise ValueError("corpus program or language id does not match the address-space table")
    if type(shard_size) is not int or shard_size < 1:
        raise ValueError("shard_size must be a positive integer")
    if type(jobs) is not int or jobs < 1:
        raise ValueError("jobs must be a positive integer")
    compiler_path = shutil.which(compiler)
    if compiler_path is None:
        raise ValueError(f"C compiler not found: {compiler}")
    version = subprocess.run(
        [compiler_path, "--version"], check=True, capture_output=True, text=True,
    ).stdout.splitlines()[0]

    flags = ["-std=c11", "-O0", *compiler_args]
    state = {
        "format": STATE_FORMAT,
        "source": {
            "program": program,
            "language_id": language_id,
            "corpus_sha256": corpus_sha256,
            "manifest_sha256": _sha256(manifest_path),
            "address_spaces_sha256": _sha256(spaces_path),
        },
        "compiler": {"path": compiler_path, "version": version, "arguments": flags},
        "shard_size_limit": shard_size,
        "builder_source_sha256": _sha256(Path(__file__)),
        "lowering_source_sha256": _sha256(Path(__file__).with_name("c_lowering.py")),
    }
    state_path = output_dir / ".build-state.json"
    if resume:
        if not state_path.is_file():
            raise ValueError(f"cannot resume without matching build state: {state_path}")
        if _json_object(state_path) != state:
            raise ValueError("existing build state does not match corpus, builder, lowerer, compiler, or shard settings")
        allowed = {".build-state.json", "build-report.json"}
        for path in output_dir.iterdir():
            is_shard_file = (
                path.name.startswith("shard-") and path.name[6:11].isdigit() and
                path.name[11:] in {".c", ".o", ".c.resume-tmp", ".o.resume-tmp"}
            )
            if path.name in allowed or is_shard_file:
                continue
            raise ValueError(f"unexpected file in resumable output directory: {path}")
    elif output_dir.exists() and any(output_dir.iterdir()):
        raise ValueError(f"output directory must be empty unless --resume is used: {output_dir}")
    output_dir.mkdir(parents=True, exist_ok=True)
    if not resume:
        state_path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    records = found = missing = instructions = lowerable = 0
    lowerable_instructions = lowerable_operations = 0
    rejection_reasons: collections.Counter[str] = collections.Counter()
    seen_addresses: set[int] = set()
    shards: list[dict] = []
    current_path: Path | None = None
    current_temp_path: Path | None = None
    current_stream = None
    current_functions = 0
    current_first = current_last = None
    current_index: int | None = None
    next_shard_index = 0
    pending = []

    def compile_shard(index: int, path: Path, count: int, first: str, last: str) -> tuple[dict, bool]:
        object_path = path.with_suffix(".o")
        reused = object_path.is_file() and object_path.stat().st_size > 0
        if not reused:
            temporary_object_path = object_path.with_name(object_path.name + ".resume-tmp")
            subprocess.run(
                [compiler_path, *flags, "-c", str(path), "-o", str(temporary_object_path)],
                check=True, capture_output=True, text=True,
            )
            temporary_object_path.replace(object_path)
        return {
            "index": index,
            "functions": count,
            "first_function": first,
            "last_function": last,
            "source_file": path.name,
            "source_sha256": _sha256(path),
            "source_bytes": path.stat().st_size,
            "object_file": object_path.name,
            "object_sha256": _sha256(object_path),
            "object_bytes": object_path.stat().st_size,
        }, reused

    def collect(future) -> None:
        shard, reused = future.result()
        shards.append(shard)
        action = "reused" if reused else "compiled"
        print(
            f"{action} shard {shard['index']}: {shard['functions']} functions, "
            f"{shard['object_bytes']} object bytes",
            file=sys.stderr, flush=True,
        )

    def finish_shard() -> None:
        nonlocal current_path, current_temp_path, current_stream, current_functions, current_first, current_last, current_index
        if current_stream is None or current_path is None or current_temp_path is None or current_index is None:
            return
        current_stream.close()
        if resume:
            if current_path.exists() and _sha256(current_path) == _sha256(current_temp_path):
                current_temp_path.unlink()
            else:
                current_temp_path.replace(current_path)
        pending.append(executor.submit(
            compile_shard, current_index, current_path, current_functions, current_first, current_last))
        if len(pending) >= jobs:
            done, _ = wait(pending, return_when=FIRST_COMPLETED)
            for future in done:
                pending.remove(future)
                collect(future)
        current_path = None
        current_temp_path = None
        current_stream = None
        current_functions = 0
        current_first = current_last = None
        current_index = None

    with ThreadPoolExecutor(max_workers=jobs) as executor:
        with _open_text(corpus_path) as stream:
            for line_no, raw in enumerate(stream, 1):
                if not raw.strip():
                    continue
                try:
                    row = json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"{corpus_path}:{line_no}: invalid JSON: {exc.msg}") from exc
                if not isinstance(row, dict) or row.get("format") != CORPUS_FORMAT:
                    raise ValueError(f"{corpus_path}:{line_no}: expected {CORPUS_FORMAT}")
                if row.get("program") != program:
                    raise ValueError(f"{corpus_path}:{line_no}: program differs from corpus manifest")
                row_instructions = row.get("instructions")
                count = row.get("instruction_count")
                if not isinstance(row_instructions, list) or type(count) is not int or count != len(row_instructions):
                    raise ValueError(f"{corpus_path}:{line_no}: malformed instruction list or count")
                records += 1
                instructions += count
                if row.get("found") is False:
                    if row.get("function") is not None or row_instructions:
                        raise ValueError(f"{corpus_path}:{line_no}: missing function has metadata or instructions")
                    missing += 1
                    continue
                if row.get("found") is not True:
                    raise ValueError(f"{corpus_path}:{line_no}: found must be a boolean")
                function = row.get("function")
                if not isinstance(function, dict) or not isinstance(function.get("address"), str):
                    raise ValueError(f"{corpus_path}:{line_no}: found function has no address")
                address_text = function["address"]
                try:
                    address = int(address_text, 16)
                except ValueError as exc:
                    raise ValueError(f"{corpus_path}:{line_no}: invalid function address") from exc
                if address in seen_addresses:
                    raise ValueError(f"{corpus_path}:{line_no}: duplicate function address {address_text}")
                seen_addresses.add(address)
                found += 1
                try:
                    source, operation_count = compile_function(row, spaces, include_runtime=False)
                except PcodeLoweringError as exc:
                    rejection_reasons[_rejection_reason(exc)] += 1
                    continue
                if current_functions == shard_size:
                    finish_shard()
                if current_stream is None:
                    current_index = next_shard_index
                    current_path = output_dir / f"shard-{current_index:05d}.c"
                    current_temp_path = (
                        output_dir / f"shard-{current_index:05d}.c.resume-tmp" if resume else current_path
                    )
                    next_shard_index += 1
                    current_stream = current_temp_path.open("w", encoding="utf-8")
                    current_stream.write(_RUNTIME.rstrip() + "\n\n")
                    current_first = address_text
                current_stream.write(source)
                current_functions += 1
                current_last = address_text
                lowerable += 1
                lowerable_instructions += count
                lowerable_operations += operation_count
        finish_shard()
        for future in pending:
            collect(future)

    if records == 0:
        raise ValueError("instruction corpus is empty")
    if type(manifest.get("exported_function_count")) is not int or records != manifest["exported_function_count"]:
        raise ValueError("exported function count does not match the corpus manifest")
    if type(manifest.get("instruction_count")) is not int or instructions != manifest["instruction_count"]:
        raise ValueError("instruction count does not match the corpus manifest")
    shards.sort(key=lambda shard: shard["index"])
    report = {
        "format": FORMAT,
        "source": {
            "program": program,
            "language_id": language_id,
            "corpus_sha256": corpus_sha256,
            "manifest_sha256": _sha256(manifest_path),
            "address_spaces_sha256": _sha256(spaces_path),
        },
        "compiler": {"path": compiler_path, "version": version, "arguments": flags},
        "shard_size_limit": shard_size,
        "jobs": jobs,
        "resumed": resume,
        "builder_source_sha256": _sha256(Path(__file__)),
        "functions": {
            "records": records,
            "found": found,
            "missing": missing,
            "lowerable": lowerable,
            "rejected": found - lowerable,
        },
        "instructions": {
            "total": instructions,
            "in_lowerable_functions": lowerable_instructions,
        },
        "pcode_operations": {"in_lowerable_functions": lowerable_operations},
        "rejection_reasons": [
            {"reason": reason, "functions": count}
            for reason, count in sorted(rejection_reasons.items(), key=lambda item: (-item[1], item[0]))
        ],
        "shards": shards,
    }
    report_path = output_dir / "build-report.json"
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("address_spaces", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--compiler", required=True, help="C compiler used to emit object files")
    parser.add_argument("--shard-size", type=int, default=500)
    parser.add_argument("--jobs", type=int, default=4, help="maximum number of concurrent compiler processes")
    parser.add_argument("--resume", action="store_true", help="verify and reuse existing shards in a matching build directory")
    parser.add_argument("--compiler-arg", action="append", default=[], help="extra argument passed to the C compiler")
    args = parser.parse_args(argv)
    try:
        report = build(
            args.corpus, args.manifest, args.address_spaces, args.output_dir,
            args.compiler, shard_size=args.shard_size, jobs=args.jobs,
            compiler_args=tuple(args.compiler_arg), resume=args.resume,
        )
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        parser.error(str(exc))
    print("lowerable functions:", report["functions"]["lowerable"])
    print("object shards:", len(report["shards"]))
    print("rejected functions:", report["functions"]["rejected"])
    print("report:", args.output_dir / "build-report.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
