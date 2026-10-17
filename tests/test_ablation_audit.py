from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.ml.ablation_audit import (
    FORMAT,
    SET_FORMAT,
    build_ablation_audit,
    main,
)

ROOT = Path(__file__).resolve().parents[1]
REPORT_SCHEMA = ROOT / "schemas/classifier-ablation-audit-v1.schema.json"
SET_SCHEMA = ROOT / "schemas/classifier-ablation-set-v1.schema.json"
SELECTIVE_FORMAT = "REVENGINSTR.SelectiveClassifier/1"
EVIDENCE_FORMAT = "REVENGINSTR.EvidenceSelectiveClassifier/1"


def manifest(format_name: str) -> dict:
    return {
        "format": format_name,
        "task": "domain",
        "classes": ["alpha", "beta"],
        "functions": 4,
        "families": 4,
        "dataset_fingerprint_sha256": "a" * 64,
        "calibration": {"source": "family_grouped_oof", "folds": 2, "seed": 7},
    }


def rows(format_name: str, *, improved: bool = False) -> list[dict]:
    outcomes = [
        ("one", "alpha", "alpha", "accept"),
        ("two", "beta", "beta", "accept"),
        ("three", "alpha", "alpha" if improved else "beta", "accept" if improved else "review"),
        ("four", "beta", "beta" if improved else "alpha", "review" if improved else "escalate"),
    ]
    return [{
        "format": format_name,
        "id": record_id,
        "family_id": f"family-{index}",
        "truth": truth,
        "prediction": prediction,
        "correct": truth == prediction,
        "confidence": 0.9 - index * 0.1,
        "action": action,
    } for index, (record_id, truth, prediction, action) in enumerate(outcomes, 1)]


def fixture() -> tuple[dict, dict[str, dict], dict[str, list[dict]], dict[str, str], dict[str, str]]:
    names = ("pcode", "without_receiver")
    classifier_manifests = {
        names[0]: manifest(SELECTIVE_FORMAT),
        names[1]: manifest(EVIDENCE_FORMAT),
    }
    predictions = {
        names[0]: rows(SELECTIVE_FORMAT),
        names[1]: rows(EVIDENCE_FORMAT, improved=True),
    }
    spec = {
        "format": SET_FORMAT,
        "baseline": names[0],
        "variants": {name: {} for name in names},
    }
    return (
        spec,
        classifier_manifests,
        predictions,
        {names[0]: "b" * 64, names[1]: "c" * 64},
        {names[0]: "d" * 64, names[1]: "e" * 64},
    )


def build(spec, classifier_manifests, predictions, manifest_hashes, prediction_hashes):
    return build_ablation_audit(
        spec,
        classifier_manifests,
        predictions,
        set_sha256="f" * 64,
        manifest_sha256=manifest_hashes,
        predictions_sha256=prediction_hashes,
    )


def test_ablation_audit_compares_paired_oof_metrics_without_ids() -> None:
    spec, manifests, predictions, manifest_hashes, prediction_hashes = fixture()
    result = build(spec, manifests, predictions, manifest_hashes, prediction_hashes)

    Draft202012Validator(json.loads(REPORT_SCHEMA.read_text(encoding="utf-8"))).validate(result)
    assert result["format"] == FORMAT
    assert result["source"]["family_grouped_oof"] is True
    assert result["source"]["oof_rows"] == 4
    baseline = result["variants"]["pcode"]
    assert baseline["comparison_to_baseline"] is None
    assert baseline["metrics"]["accuracy"] == 0.5
    candidate = result["variants"]["without_receiver"]
    assert candidate["classifier_format"] == EVIDENCE_FORMAT
    assert candidate["metrics"]["accuracy"] == 1.0
    assert candidate["comparison_to_baseline"] == {
        "changed_predictions": 2,
        "fixed_errors": 2,
        "introduced_errors": 0,
        "net_correct_change": 2,
        "accuracy_delta": 0.5,
        "balanced_accuracy_delta": 0.5,
        "macro_f1_delta": 0.5,
        "accepted_coverage_delta": 0.25,
        "accepted_precision_delta": 0.0,
    }
    encoded = json.dumps(result)
    assert '"id"' not in encoded
    assert "family-1" not in encoded


@pytest.mark.parametrize("mutation, message", [
    (lambda manifests, preds: manifests["without_receiver"].update(dataset_fingerprint_sha256="0" * 64), "population differs"),
    (lambda manifests, preds: manifests["without_receiver"]["calibration"].update(seed=8), "population differs"),
    (lambda manifests, preds: preds["without_receiver"][0].update(family_id="other-family"), "family or truth differs"),
    (lambda manifests, preds: preds["without_receiver"].pop(), "row count disagrees"),
    (lambda manifests, preds: preds["without_receiver"][0].update(correct=False), "correct flag disagrees"),
])
def test_ablation_audit_rejects_unpaired_or_invalid_variants(mutation, message: str) -> None:
    spec, manifests, predictions, manifest_hashes, prediction_hashes = fixture()
    mutation(manifests, predictions)
    with pytest.raises(ValueError, match=message):
        build(spec, manifests, predictions, manifest_hashes, prediction_hashes)


def test_ablation_audit_cli_checks_pinned_inputs_and_writes_report(tmp_path: Path, capsys) -> None:
    specs = {}
    variants = {}
    for name, format_name, improved in [
        ("baseline", SELECTIVE_FORMAT, False),
        ("variant", EVIDENCE_FORMAT, True),
    ]:
        manifest_path = tmp_path / f"{name}-manifest.json"
        prediction_path = tmp_path / f"{name}-oof.jsonl"
        manifest_path.write_text(json.dumps(manifest(format_name)), encoding="utf-8")
        prediction_path.write_text("".join(json.dumps(row) + "\n" for row in rows(format_name, improved=improved)), encoding="utf-8")
        variants[name] = {
            "manifest_path": manifest_path.name,
            "manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
            "oof_predictions_path": prediction_path.name,
            "oof_predictions_sha256": hashlib.sha256(prediction_path.read_bytes()).hexdigest(),
        }
    spec_path = tmp_path / "ablation-set.json"
    spec_path.write_text(json.dumps({"format": SET_FORMAT, "baseline": "baseline", "variants": variants}), encoding="utf-8")
    Draft202012Validator(json.loads(SET_SCHEMA.read_text(encoding="utf-8"))).validate(
        json.loads(spec_path.read_text(encoding="utf-8"))
    )
    output = tmp_path / "nested" / "audit.json"

    assert main([str(spec_path), "--output", str(output)]) == 0
    result = json.loads(output.read_text(encoding="utf-8"))
    Draft202012Validator(json.loads(REPORT_SCHEMA.read_text(encoding="utf-8"))).validate(result)
    assert result["variants"]["variant"]["comparison_to_baseline"]["fixed_errors"] == 2
    assert "variants: 2" in capsys.readouterr().out

    variants["variant"]["oof_predictions_sha256"] = "0" * 64
    spec_path.write_text(json.dumps({"format": SET_FORMAT, "baseline": "baseline", "variants": variants}), encoding="utf-8")
    with pytest.raises(ValueError, match="OOF prediction SHA-256 mismatch"):
        main([str(spec_path), "--output", str(output)])
