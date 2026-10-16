from __future__ import annotations

import json
from pathlib import Path

from revenginstr.evidence.structural import structural_metrics
from revenginstr.ml.evidence_selective import FORMAT, classify_rows, train_evidence_selective_classifier
from revenginstr.ml.evidence_tokens import EVIDENCE_FORMAT, augment_text, bucket_number, load_evidence


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def text(label: str, variant: int) -> str:
    opcode = "INT_ADD" if label == "alpha" else "INT_XOR"
    tail = "INT_AND" if label == "alpha" else "STORE"
    tail_args = "out=v2:4 in=v1:4 in=const:small:0xff:4" if tail == "INT_AND" else "addr=reg:4 value=v1:4"
    return (
        "ARCH=X8632\nENDIAN=LE\nPTR_SIZE=4\n"
        "o0 LOAD out=v0:4 addr=reg:4\n"
        f"o1 {opcode} out=v1:4 in=v0:4 in=const:small:0x{4 + variant:x}:4\n"
        f"o2 {tail} {tail_args}\n"
        "o3 RETURN ret=v1:4\n"
    )


def test_structural_and_bucketed_evidence_contract() -> None:
    metrics = structural_metrics(text("alpha", 1))
    assert metrics["op_count"] == 4
    assert metrics["load_count"] == 1
    assert metrics["return_count"] == 1
    assert bucket_number(0.37) == "ratio_+4"
    document, count = augment_text(text("alpha", 1), {"callgraph.out_degree": 9.0})
    assert count > 20
    assert "EV|external.callgraph.out_degree|8_15" in document
    assert "ARCH=X8632" in document


def test_evidence_selective_train_and_infer(tmp_path: Path) -> None:
    dataset = tmp_path / "dataset"
    families_path = tmp_path / "families.jsonl"
    evidence_path = tmp_path / "evidence.jsonl"
    model_dir = tmp_path / "model"
    rows: list[dict] = []
    families: list[dict] = []
    evidence: list[dict] = []
    for label in ("alpha", "beta"):
        for family_index in range(4):
            family_id = f"family-{label}-{family_index}"
            for member in range(2):
                record_id = f"{label}-{family_index}-{member}"
                rows.append({"id": record_id, "text": text(label, family_index + member), "labels": {"domain": label}})
                families.append({"format": "REVENGINSTR.FunctionFamilies/1", "id": record_id, "family_id": family_id, "family_size": 2})
                evidence.append({
                    "format": EVIDENCE_FORMAT,
                    "id": record_id,
                    "features": {
                        "has_callgraph": True,
                        "callgraph.out_degree": float(2 + family_index if label == "alpha" else 12 + family_index),
                        "receiver.call_count": float(member),
                    },
                })
    write_jsonl(dataset / "train.jsonl", rows[:8])
    write_jsonl(dataset / "validation.jsonl", rows[8:12])
    write_jsonl(dataset / "test.jsonl", rows[12:])
    write_jsonl(families_path, families)
    write_jsonl(evidence_path, evidence)

    manifest = train_evidence_selective_classifier(
        dataset, families_path, model_dir,
        evidence_path=evidence_path, task="domain", classes=["alpha", "beta"],
        folds=2, seed=9, accept_precision=0.8, review_precision=0.5,
        min_class_calibration_examples=2, min_class_threshold_examples=1,
        min_ood_threshold_examples=1,
    )
    assert manifest["format"] == FORMAT
    assert manifest["external_evidence_rows"] == 16
    assert manifest["mean_evidence_tokens"] > 20
    assert manifest["leakage_policy"]["numeric_evidence_bucketed"] is True

    import joblib

    artifact = joblib.load(model_dir / "classifier.joblib")
    external = load_evidence(evidence_path)
    inferred = classify_rows(
        artifact,
        [{"id": "alpha-0-0", "model_text": text("alpha", 0)}],
        evidence=external,
    )
    assert inferred[0]["format"] == FORMAT
    assert inferred[0]["external_evidence_present"] is True
    assert inferred[0]["evidence_token_count"] > 20
    assert inferred[0]["action"] in {"accept", "review", "escalate"}
