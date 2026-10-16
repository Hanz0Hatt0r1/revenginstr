from __future__ import annotations

import json
from pathlib import Path

import pytest

from revenginstr.validation import DRIFT_AUDIT_FORMAT, FROZEN_VALIDATION_FORMAT
from revenginstr.validation.drift import audit_drift
from revenginstr.validation.frozen import freeze_validation


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def _corpus_row(index: int, *, external: bool = False, failed: bool = False) -> dict:
    row = {
        "format": "REVENGINSTR.PcodeCorpus/1",
        "program": "game.exe",
        "source_entry": f"{0x401000 + index * 0x10:08x}",
        "source_name": f"FUN_{0x401000 + index * 0x10:08x}",
        "external": external,
        "decompile_status": "failed" if failed else "ok",
    }
    if not failed:
        row["metrics"] = {"emitted_ops": 1, "truncated": False}
        row["model_text"] = "ARCH=X8632\nENDIAN=LE\nPTR_SIZE=4\no0 RETURN\n"
    return row


def test_freeze_validation_is_deterministic_identity_disjoint_and_immutable(tmp_path: Path) -> None:
    source = tmp_path / "source.jsonl"
    exclusion = tmp_path / "train-trace.jsonl"
    out_a = tmp_path / "frozen-a"
    out_b = tmp_path / "frozen-b"
    rows = [_corpus_row(index) for index in range(12)]
    rows.append(_corpus_row(50, external=True))
    rows.append(_corpus_row(51, failed=True))
    _write_jsonl(source, rows)
    _write_jsonl(
        exclusion,
        [
            {
                "id": "training-row",
                "program": "game.exe",
                "source_entry": rows[2]["source_entry"],
            }
        ],
    )

    first = freeze_validation(
        source,
        out_a,
        exclude_traces=[exclusion],
        limit=5,
        tag="smoke",
    )
    second = freeze_validation(
        source,
        out_b,
        exclude_traces=[exclusion],
        limit=5,
        tag="another-metadata-tag",
    )
    assert first["format"] == FROZEN_VALIDATION_FORMAT
    assert first["source_corpus"]["excluded_overlap"] == 1
    assert first["frozen_corpus"]["sha256"] == second["frozen_corpus"]["sha256"]
    frozen_rows = [json.loads(line) for line in (out_a / "corpus.jsonl").read_text().splitlines()]
    assert len(frozen_rows) == 5
    assert all(row["id"] == f"{row['program']}:{row['source_entry']}" for row in frozen_rows)
    assert rows[2]["source_entry"] not in {row["source_entry"] for row in frozen_rows}

    with pytest.raises(FileExistsError):
        freeze_validation(source, out_a, exclude_traces=[exclusion], limit=5)


def _classified(prefix: str, count: int, *, shifted: bool, routed: bool) -> list[dict]:
    rows = []
    for index in range(count):
        prediction = "media" if shifted and index < count // 2 else ("engine" if index % 2 else "game")
        base_action = "accept" if index < count * 3 // 5 else ("review" if index < count * 4 // 5 else "escalate")
        action = base_action
        changed = False
        if routed and base_action == "accept" and index % 4 == 0:
            action = "escalate"
            changed = True
        row = {
            "id": f"{prefix}:{index}",
            "prediction": prediction,
            "base_action": base_action,
            "action": action,
            "confidence": 0.92 if not shifted else 0.71,
            "raw_confidence": 0.88 if not shifted else 0.68,
            "family_similarity": 0.82 if not shifted else 0.55,
            "competing_similarity": 0.25 if not shifted else 0.46,
            "contrast_margin": 0.57 if not shifted else 0.09,
            "probabilities": {"game": 0.7, "engine": 0.2, "media": 0.1},
        }
        if routed:
            row["accept_router_changed"] = changed
        rows.append(row)
    return rows


def test_drift_audit_reports_unlabeled_shift_and_router_intervention() -> None:
    reference = _classified("ref", 100, shifted=False, routed=True)
    frozen = _classified("new", 40, shifted=True, routed=True)
    # Reference changes 15/60 accepts; frozen changes 6/24 accepts: same intervention rate.
    reference_evidence = {
        row["id"]: {"has_callgraph": 1.0, "has_receiver_types": 1.0}
        for row in reference
    }
    frozen_evidence = {
        row["id"]: {"has_callgraph": 1.0}
        for row in frozen
    }
    summary = audit_drift(
        reference,
        frozen,
        reference_evidence=reference_evidence,
        frozen_evidence=frozen_evidence,
    )
    assert summary["format"] == DRIFT_AUDIT_FORMAT
    assert summary["labels_available"] is False
    assert summary["reference_rows"] == 100
    assert summary["frozen_rows"] == 40
    assert summary["categorical_shift"]["prediction"]["js_divergence_bits"] > 0.0
    assert summary["router_intervention"]["reference_change_fraction_accept"] == pytest.approx(0.25)
    assert summary["router_intervention"]["frozen_change_fraction_accept"] == pytest.approx(0.25)
    assert summary["router_intervention"]["accept_change_rate_ratio"] == pytest.approx(1.0)
    assert summary["evidence_shift"]["core"]["has_callgraph"]["delta"] == pytest.approx(0.0)
    assert summary["evidence_shift"]["core"]["has_receiver_types"]["delta"] == pytest.approx(-1.0)
    assert summary["severity"]["diagnostic_only"] is True
    assert summary["severity"]["level"] == "high"


def test_drift_audit_can_use_router_manifest_for_reference_rate() -> None:
    reference = _classified("ref", 50, shifted=False, routed=False)
    frozen = _classified("new", 20, shifted=False, routed=True)
    manifest = {
        "calibration": {
            "legacy_accept_examples": 30,
            "kept_examples": 27,
        }
    }
    summary = audit_drift(reference, frozen, router_manifest=manifest)
    assert summary["router_intervention"]["reference_changed"] == 3
    assert summary["router_intervention"]["reference_change_fraction_accept"] == pytest.approx(0.1)
