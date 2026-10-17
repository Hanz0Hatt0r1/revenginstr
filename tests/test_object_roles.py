from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.benchmark import TOOLS
from revenginstr.object_roles import (
    FEATURE_FORMAT,
    FORMAT,
    cluster_object_role_candidates,
    main,
)

ROOT = Path(__file__).resolve().parents[1]
FEATURE_SCHEMA = json.loads((ROOT / "schemas/object-role-feature-set-v1.schema.json").read_text())
REPORT_SCHEMA = json.loads((ROOT / "schemas/object-role-cluster-audit-v1.schema.json").read_text())


def feature(group: str, digest: str, source_index: int = 1) -> dict:
    return {
        "group": group,
        "feature_sha256": digest,
        "support": [{
            "source_format": f"REVENGINSTR.{group}/1",
            "source_sha256": "f" * 64,
            "source_record_index": source_index,
        }],
    }


def feature_set() -> list[dict]:
    return [
        {
            "format": FEATURE_FORMAT,
            "program_id": "analysis:fixture",
            "function_entry": "00401000",
            "features": [
                feature("receiver", "a" * 64), feature("receiver", "b" * 64),
                feature("field", "c" * 64), feature("vtable_slot", "d" * 64),
                feature("effect_ir", "e" * 64),
            ],
        },
        {
            "format": FEATURE_FORMAT,
            "program_id": "analysis:fixture",
            "function_entry": "00402000",
            "features": [
                feature("receiver", "a" * 64), feature("receiver", "6" * 64),
                feature("field", "c" * 64), feature("vtable_slot", "d" * 64),
                feature("effect_ir", "e" * 64),
            ],
        },
        {
            "format": FEATURE_FORMAT,
            "program_id": "analysis:fixture",
            "function_entry": "00403000",
            "features": [feature("receiver", "7" * 64), feature("effect_ir", "e" * 64)],
        },
        {
            "format": FEATURE_FORMAT,
            "program_id": "analysis:fixture",
            "function_entry": "00404000",
            "features": [],
        },
    ]


def test_object_role_clustering_emits_provenance_linked_similarity_candidates() -> None:
    rows = feature_set()
    for row in rows:
        Draft202012Validator(FEATURE_SCHEMA).validate(row)

    report = cluster_object_role_candidates(rows, feature_set_sha256="9" * 64)

    Draft202012Validator.check_schema(REPORT_SCHEMA)
    Draft202012Validator(REPORT_SCHEMA).validate(report)
    assert report["format"] == FORMAT
    assert report["source"]["function_count"] == 4
    assert report["source"]["candidate_pairs_considered"] == 3
    assert report["source"]["candidate_pair_count"] == 1
    pair = report["candidate_pairs"][0]
    assert pair["left_function_entry"] == "00401000"
    assert pair["right_function_entry"] == "00402000"
    assert pair["similarity"] == pytest.approx(5 / 6)
    assert pair["shared_groups"] == ["receiver", "field", "vtable_slot", "effect_ir"]
    assert len(report["clusters"]) == 1
    assert report["clusters"][0]["member_function_entries"] == ["00401000", "00402000"]
    assert set(report["clusters"][0]["pair_ids"]) == {pair["pair_id"]}


@pytest.mark.parametrize("mutation, message", [
    (lambda rows: rows[1].update(program_id="other:program"), "multiple program ids"),
    (lambda rows: rows[0]["features"].append(rows[0]["features"][0]), "duplicate group/feature"),
    (lambda rows: rows[0]["features"][0]["support"][0].update(source_record_index=True), "invalid source_record_index"),
])
def test_object_role_feature_contract_fails_closed(mutation, message: str) -> None:
    rows = feature_set()
    mutation(rows)
    with pytest.raises(ValueError, match=message):
        cluster_object_role_candidates(rows, feature_set_sha256="9" * 64)


def test_object_role_cluster_budget_and_minimum_group_gate() -> None:
    rows = feature_set()
    with pytest.raises(ValueError, match="candidate-pair budget exceeded"):
        cluster_object_role_candidates(rows, feature_set_sha256="9" * 64, max_candidate_pairs=2)

    report = cluster_object_role_candidates(
        rows, feature_set_sha256="9" * 64, similarity_threshold=0.99, min_shared_groups=2
    )
    assert report["candidate_pairs"] == []
    assert report["clusters"] == []


def test_object_role_cluster_cli_hashes_input_and_writes_report(tmp_path: Path, capsys) -> None:
    assert TOOLS["object-role-clusters"] == ("revenginstr.object_roles", "main")
    source = tmp_path / "features.jsonl"
    source.write_text("".join(json.dumps(row) + "\n" for row in feature_set()), encoding="utf-8")
    output = tmp_path / "nested" / "clusters.json"

    assert main([str(source), "--output", str(output)]) == 0

    report = json.loads(output.read_text(encoding="utf-8"))
    Draft202012Validator(REPORT_SCHEMA).validate(report)
    assert report["source"]["feature_set_sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
    assert "candidate pairs: 1" in capsys.readouterr().out
