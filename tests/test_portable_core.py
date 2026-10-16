from __future__ import annotations

import json
from pathlib import Path

from revenginstr.ood.foreign_guard import apply_guard
from revenginstr.pcode.audit import build_report


def sample_corpus() -> list[dict]:
    fixture = Path(__file__).resolve().parent / "fixtures/pcode-corpus/synthetic.jsonl"
    return [json.loads(line) for line in fixture.read_text(encoding="utf-8").splitlines()]


def test_portable_audit_passes_clean_corpus() -> None:
    report = build_report(sample_corpus())
    assert report["format"] == "REVENGINSTR.PcodeAudit/1"
    assert report["corpus"]["portable_contract_pass"] is True
    assert report["corpus"]["architecture"] == {"X8632": 1}
    assert report["corpus"]["pointer_size"] == {"4": 1}
    assert report["corpus"]["leakage_findings"] == []


def test_portable_audit_detects_join_key_leakage() -> None:
    rows = sample_corpus()
    rows[0]["model_text"] += "sample.exe\n"
    report = build_report(rows)
    assert report["corpus"]["portable_contract_pass"] is False
    assert {item["reason"] for item in report["corpus"]["leakage_findings"]} == {"program_leaked"}


def test_foreign_guard_is_monotone() -> None:
    rows = [
        {"id": "a", "action": "accept", "family_similarity": 0.8, "contrast_margin": 0.12},
        {"id": "b", "action": "accept", "family_similarity": 0.6, "contrast_margin": 0.12},
        {"id": "c", "action": "accept", "family_similarity": 0.8, "contrast_margin": 0.01},
        {"id": "d", "action": "review", "family_similarity": 0.99, "contrast_margin": 0.99},
        {"id": "e", "action": "escalate", "family_similarity": 0.99, "contrast_margin": 0.99},
    ]
    guarded, summary = apply_guard(rows, 0.70, 0.05)
    assert [row["action"] for row in guarded] == ["accept", "review", "review", "review", "escalate"]
    assert summary["changed_accepts"] == 2
    assert summary["promotions"] == 0
    assert summary["accept_retention"] == 1 / 3


def test_foreign_guard_keeps_per_class_accept_thresholds() -> None:
    rows = [{
        "action": "accept",
        "family_similarity": 0.75,
        "contrast_margin": 0.10,
        "ood_accept_threshold": 0.80,
        "contrast_accept_threshold": 0.12,
    }]
    guarded, summary = apply_guard(rows, 0.70, 0.05)
    assert guarded[0]["action"] == "review"
    assert guarded[0]["foreign_similarity_floor"] == 0.80
    assert guarded[0]["foreign_contrast_floor"] == 0.12
    assert guarded[0]["foreign_guard_reasons"] == [
        "family_similarity_below_floor",
        "contrast_margin_below_floor",
    ]
    assert summary["promotions"] == 0


def test_generic_exporter_has_project_neutral_contract() -> None:
    root = Path(__file__).resolve().parents[1]
    text = (root / "ghidra/PortablePcodeCorpusExporter.java").read_text(encoding="utf-8")
    assert 'FORMAT = "REVENGINSTR.PcodeCorpus/1"' in text
    assert "MAX_MODEL_OPS = 256" in text
    assert "PortablePcodeCorpusExporter" in text
    assert "Nevergone" not in text
    assert "SHIFT" not in text
    assert 'text.append("ARCH=")' in text
    assert 'text.append("PTR_SIZE=")' in text
    assert "resolveCallTarget" in text
    assert "offset & ~1L" in text
    assert "functions.getFunctionAt(normalized)" in text
    assert "source_entry" in text
    assert "source_name" in text


def test_generic_runner_is_read_only_and_isolated() -> None:
    root = Path(__file__).resolve().parents[1]
    text = (root / "scripts/run_ghidra_pcode_export.sh").read_text(encoding="utf-8")
    assert "-readOnly" in text
    assert "-noanalysis" in text
    assert "-recursive" in text
    assert "mktemp -d" in text
    assert "PortablePcodeCorpusExporter.java" in text
