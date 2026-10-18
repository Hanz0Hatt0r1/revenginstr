"""Build a hash-pinned JSON and Markdown dashboard from benchmark reports."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any

MANIFEST_FORMAT = "REVENGINSTR.KPIDashboardManifest/1"
FORMAT = "REVENGINSTR.KPIDashboard/1"
UNITS = {"fraction", "percent", "count", "score", "seconds"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return value


def _check_unit_value(value: float, unit: str, name: str) -> None:
    if unit == "fraction" and not 0.0 <= value <= 1.0:
        raise ValueError(f"{name} fraction must be in [0, 1]")
    if unit == "percent" and not 0.0 <= value <= 100.0:
        raise ValueError(f"{name} percent must be in [0, 100]")
    if unit == "count" and (value < 0.0 or not value.is_integer()):
        raise ValueError(f"{name} count must be a non-negative integer")
    if unit == "seconds" and value < 0.0:
        raise ValueError(f"{name} seconds must be non-negative")


def _validate_manifest(manifest: dict[str, Any]) -> None:
    if manifest.get("format") != MANIFEST_FORMAT:
        raise ValueError(f"manifest format must be {MANIFEST_FORMAT}")
    dashboard = manifest.get("dashboard")
    if not isinstance(dashboard, dict):
        raise ValueError("manifest missing dashboard object")
    for field in ("id", "title"):
        if not isinstance(dashboard.get(field), str) or not dashboard[field].strip():
            raise ValueError(f"dashboard.{field} must be a non-empty string")
    sources = manifest.get("sources")
    if not isinstance(sources, dict) or not sources:
        raise ValueError("manifest sources must be a non-empty object")
    for source_id, source in sources.items():
        if not isinstance(source_id, str) or not source_id or not isinstance(source, dict):
            raise ValueError("source entries must be named objects")
        for field in ("path", "sha256", "format"):
            if not isinstance(source.get(field), str) or not source[field]:
                raise ValueError(f"source {source_id!r} missing {field}")
        if not re.fullmatch(r"[a-fA-F0-9]{64}", source["sha256"]):
            raise ValueError(f"source {source_id!r} has invalid SHA-256")
    kpis = manifest.get("kpis")
    if not isinstance(kpis, list) or not kpis:
        raise ValueError("manifest kpis must be a non-empty array")
    seen: set[str] = set()
    for index, kpi in enumerate(kpis, 1):
        if not isinstance(kpi, dict):
            raise ValueError(f"KPI {index} must be an object")
        for field in ("id", "label", "source", "json_pointer", "unit"):
            if not isinstance(kpi.get(field), str) or not kpi[field]:
                raise ValueError(f"KPI {index} missing {field}")
        if kpi["id"] in seen:
            raise ValueError(f"duplicate KPI id: {kpi['id']}")
        seen.add(kpi["id"])
        if kpi["source"] not in sources:
            raise ValueError(f"KPI {kpi['id']!r} references unknown source")
        if kpi["unit"] not in UNITS:
            raise ValueError(f"KPI {kpi['id']!r} has unsupported unit")
        pointer = kpi["json_pointer"]
        if pointer and not pointer.startswith("/"):
            raise ValueError(f"KPI {kpi['id']!r} JSON Pointer must be empty or start with '/'")
        if re.search(r"~(?![01])", pointer):
            raise ValueError(f"KPI {kpi['id']!r} JSON Pointer has an invalid escape")
        has_min = "minimum" in kpi and kpi["minimum"] is not None
        has_max = "maximum" in kpi and kpi["maximum"] is not None
        if not has_min and not has_max:
            raise ValueError(f"KPI {kpi['id']!r} needs a minimum or maximum")
        for field in ("minimum", "maximum"):
            value = kpi.get(field)
            if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value)):
                raise ValueError(f"KPI {kpi['id']!r} {field} must be finite numeric")
            if value is not None:
                _check_unit_value(float(value), kpi["unit"], f"KPI {kpi['id']!r} {field}")
        if has_min and has_max and kpi["minimum"] > kpi["maximum"]:
            raise ValueError(f"KPI {kpi['id']!r} minimum exceeds maximum")


def _pointer_value(document: Any, pointer: str) -> Any:
    if pointer == "":
        return document
    current = document
    for raw_token in pointer[1:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict):
            if token not in current:
                return None
            current = current[token]
        elif isinstance(current, list):
            if not token.isdigit() or (len(token) > 1 and token.startswith("0")):
                return None
            index = int(token)
            if index >= len(current):
                return None
            current = current[index]
        else:
            return None
    return current


def _display(value: float | None, unit: str) -> str:
    if value is None:
        return "unavailable"
    if unit == "fraction":
        return f"{value * 100:.2f}%"
    if unit == "percent":
        return f"{value:.2f}%"
    if unit == "count":
        return f"{value:g}"
    if unit == "seconds":
        return f"{value:.3f} s"
    return f"{value:.4f}"


def _target_text(kpi: dict[str, Any]) -> str:
    minimum = kpi.get("minimum")
    maximum = kpi.get("maximum")
    if minimum is not None and maximum is not None:
        return f"{_display(float(minimum), kpi['unit'])}–{_display(float(maximum), kpi['unit'])}"
    if minimum is not None:
        return f"≥ {_display(float(minimum), kpi['unit'])}"
    return f"≤ {_display(float(maximum), kpi['unit'])}"


def build_dashboard(manifest_path: Path) -> tuple[dict[str, Any], str]:
    manifest_path = manifest_path.resolve()
    manifest = _read_object(manifest_path)
    _validate_manifest(manifest)
    source_values: dict[str, dict[str, Any]] = {}
    source_reports: list[dict[str, str]] = []
    for source_id, source in sorted(manifest["sources"].items()):
        source_path = Path(source["path"]).expanduser()
        if not source_path.is_absolute():
            source_path = (manifest_path.parent / source_path).resolve()
        else:
            source_path = source_path.resolve()
        actual_hash = sha256_file(source_path)
        if actual_hash.lower() != source["sha256"].lower():
            raise ValueError(f"source {source_id!r} SHA-256 mismatch")
        value = _read_object(source_path)
        if value.get("format") != source["format"]:
            raise ValueError(f"source {source_id!r} format mismatch")
        source_values[source_id] = value
        source_reports.append({"id": source_id, "format": source["format"], "sha256": actual_hash})

    kpi_reports: list[dict[str, Any]] = []
    for kpi in manifest["kpis"]:
        raw = _pointer_value(source_values[kpi["source"]], kpi["json_pointer"])
        if raw is None:
            value = None
            status = "unavailable"
            reason = "source metric is absent or null"
        elif isinstance(raw, bool) or not isinstance(raw, (int, float)) or not math.isfinite(raw):
            raise ValueError(f"KPI {kpi['id']!r} source value must be finite numeric or null")
        else:
            value = float(raw)
            _check_unit_value(value, kpi["unit"], f"KPI {kpi['id']!r} source value")
            passed = (
                (kpi.get("minimum") is None or value >= float(kpi["minimum"]))
                and (kpi.get("maximum") is None or value <= float(kpi["maximum"]))
            )
            status = "pass" if passed else "fail"
            reason = None
        kpi_reports.append({
            "id": kpi["id"],
            "label": kpi["label"],
            "source": kpi["source"],
            "json_pointer": kpi["json_pointer"],
            "value": value,
            "display_value": _display(value, kpi["unit"]),
            "unit": kpi["unit"],
            "minimum": kpi.get("minimum"),
            "maximum": kpi.get("maximum"),
            "target": _target_text(kpi),
            "status": status,
            "reason": reason,
            "note": kpi.get("note"),
        })

    statuses = {row["status"] for row in kpi_reports}
    overall = "fail" if "fail" in statuses else "incomplete" if "unavailable" in statuses else "pass"
    dashboard = manifest["dashboard"]
    report = {
        "format": FORMAT,
        "manifest_sha256": sha256_file(manifest_path),
        "dashboard": {
            "id": dashboard["id"],
            "title": dashboard["title"],
            "description": dashboard.get("description"),
        },
        "status": overall,
        "sources": source_reports,
        "kpis": kpi_reports,
    }
    markdown = render_markdown(report)
    return report, markdown


def _cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ").strip()


def render_markdown(report: dict[str, Any]) -> str:
    dashboard = report["dashboard"]
    lines = [f"# {dashboard['title']}", "", f"**Status:** {report['status'].upper()}"]
    if dashboard.get("description"):
        lines.extend(["", dashboard["description"]])
    lines.extend([
        "",
        "| KPI | Actual | Target | Status | Source |",
        "| --- | ---: | --- | --- | --- |",
    ])
    for row in report["kpis"]:
        lines.append("| " + " | ".join(_cell(str(value)) for value in (
            row["label"], row["display_value"], row["target"], row["status"].upper(), row["source"],
        )) + " |")
    for row in report["kpis"]:
        if row.get("note") or row.get("reason"):
            detail = row.get("note") or row.get("reason")
            lines.extend(["", f"- **{_cell(row['label'])}:** {_cell(str(detail))}"])
    lines.extend(["", "## Sources", "", "| ID | Format | SHA-256 |", "| --- | --- | --- |"])
    for source in report["sources"]:
        lines.append(f"| {source['id']} | {source['format']} | `{source['sha256']}` |")
    lines.extend([
        "",
        "Unavailable metrics remain incomplete; they are not treated as passes.",
        "",
        f"Manifest SHA-256: `{report['manifest_sha256']}`",
        "",
    ])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--json-output", type=Path, required=True)
    parser.add_argument("--markdown-output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report, markdown = build_dashboard(args.manifest)
        outputs = {args.json_output.resolve(), args.markdown_output.resolve()}
        if len(outputs) != 2:
            raise ValueError("JSON and Markdown outputs must be different files")
        manifest = _read_object(args.manifest)
        inputs = {args.manifest.resolve()}
        for source in manifest.get("sources", {}).values():
            path = Path(source["path"]).expanduser()
            inputs.add(path.resolve() if path.is_absolute() else (args.manifest.resolve().parent / path).resolve())
        if outputs & inputs:
            raise ValueError("dashboard output must not overwrite its manifest or a source report")
        for path, content in (
            (args.json_output, json.dumps(report, indent=2, sort_keys=True) + "\n"),
            (args.markdown_output, markdown),
        ):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        parser.exit(2, f"dashboard failed: {exc}\n")
    print("dashboard status:", report["status"])
    print("KPI count:", len(report["kpis"]))
    print("JSON:", args.json_output)
    print("Markdown:", args.markdown_output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
