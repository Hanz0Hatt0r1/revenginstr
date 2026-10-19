from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from revenginstr.callind_inventory import inventory, read_call_evidence, read_flows, read_population

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/callind-inventory"


def test_inventory_reconciles_counts_and_keeps_missing_evidence_visible() -> None:
    rows, summary = inventory(
        FIXTURES / "population.jsonl",
        [FIXTURES / "flow.tsv"],
        [FIXTURES / "evidence.jsonl"],
    )

    functions = {row["function_entry"]: row for row in rows if row["record_kind"] == "function"}
    sites = [row for row in rows if row["record_kind"] == "callind_site"]
    assert functions["00401000"]["count_reconciliation"] == "matched"
    assert functions["00402000"]["observed_callind_count"] == 0
    assert functions["00403000"]["count_reconciliation"] == "lower_bound"
    assert functions["00403000"]["canonical_truncated"] is True
    assert functions["00404000"]["count_reconciliation"] == "failed"
    assert functions["00405000"]["acquisition_state"] == "export_missing"
    assert functions["00405000"]["declared_acquisition_state"] == "complete"
    assert functions["00406000"]["count_reconciliation"] == "failed"
    assert functions["00407000"]["count_reconciliation"] == "failed"
    assert functions["00408000"]["count_reconciliation"] == "not_exported"
    assert functions["00409000"]["count_reconciliation"] == "unknown"

    assert len(sites) == 2
    assert sites[0]["classification"] == "unknown"
    assert sites[0]["target_expression"] == "LOAD(register:0008:4){depth-limit}"
    assert sites[0]["expression_markers"] == ["depth-limit"]
    assert sites[1]["expression_status"] == "missing"
    assert sites[1]["indirect_call_evidence_source"] is None
    assert summary["population_functions"] == 9
    assert summary["callind_sites"] == 2
    assert summary["canonical_truncated_functions"] == 1
    assert summary["site_classification_counts"] == {"unknown": 2}
    assert summary["sites_with_expression_evidence"] == 1
    assert summary["sites_missing_expression_evidence"] == 1
    assert summary["expected_callind_count_total"] == 3
    assert summary["observed_callind_count_total"] == 2


def test_inventory_schemas_accept_fixture_and_output_rows() -> None:
    population_schema = json.loads((ROOT / "schemas/callind-population-v1.schema.json").read_text())
    inventory_schema = json.loads((ROOT / "schemas/callind-inventory-v1.schema.json").read_text())
    summary_schema = json.loads((ROOT / "schemas/callind-inventory-summary-v1.schema.json").read_text())
    for schema in (population_schema, inventory_schema, summary_schema):
        Draft202012Validator.check_schema(schema)

    population_validator = Draft202012Validator(population_schema)
    for line in (FIXTURES / "population.jsonl").read_text().splitlines():
        population_validator.validate(json.loads(line))

    rows, summary = inventory(
        FIXTURES / "population.jsonl",
        [FIXTURES / "flow.tsv"],
        [FIXTURES / "evidence.jsonl"],
    )
    output_validator = Draft202012Validator(inventory_schema)
    for row in rows:
        output_validator.validate(row)
    Draft202012Validator(summary_schema).validate(summary)


def test_inventory_rejects_evidence_with_wrong_argument_count(tmp_path: Path) -> None:
    evidence = tmp_path / "evidence.jsonl"
    row = json.loads((FIXTURES / "evidence.jsonl").read_text())
    row["arg_count"] = 0
    evidence.write_text(json.dumps(row) + "\n")
    with pytest.raises(ValueError, match="arg_count"):
        inventory(FIXTURES / "population.jsonl", [FIXTURES / "flow.tsv"], [evidence])


def test_readers_reject_unmatched_sites_and_duplicate_population(tmp_path: Path) -> None:
    evidence_row = json.loads((FIXTURES / "evidence.jsonl").read_text())
    evidence_row["call_address"] = "0x0040100c"
    evidence = tmp_path / "unmatched.jsonl"
    evidence.write_text(json.dumps(evidence_row) + "\n")
    with pytest.raises(ValueError, match="no exact CALLIND flow match"):
        inventory(FIXTURES / "population.jsonl", [FIXTURES / "flow.tsv"], [evidence])

    duplicate = tmp_path / "population.jsonl"
    lines = (FIXTURES / "population.jsonl").read_text().splitlines()
    duplicate.write_text("\n".join(lines + [lines[0]]) + "\n")
    with pytest.raises(ValueError, match="duplicate population function"):
        read_population(duplicate)


def test_population_reader_rejects_duplicate_json_keys(tmp_path: Path) -> None:
    population = tmp_path / "duplicate-key.jsonl"
    row = (FIXTURES / "population.jsonl").read_text().splitlines()[0]
    population.write_text(row.replace('"program_id":"sample-program"', '"program_id":"sample-program","program_id":"other"') + "\n")
    with pytest.raises(ValueError, match="duplicate JSON key"):
        read_population(population)


def test_summary_keeps_distinct_empty_evidence_artifacts(tmp_path: Path) -> None:
    first = tmp_path / "empty-one.jsonl"
    second = tmp_path / "empty-two.jsonl"
    first.write_text("")
    second.write_text("")
    _, summary = inventory(
        FIXTURES / "population.jsonl",
        [FIXTURES / "flow.tsv"],
        [FIXTURES / "evidence.jsonl", first, second],
    )
    assert len(summary["indirect_call_evidence_artifacts"]) == 3


def test_readers_reject_flow_outside_canonical_population() -> None:
    population, _ = read_population(FIXTURES / "population.jsonl")
    flows, _ = read_flows([FIXTURES / "flow.tsv"])
    extra = dict(next(iter(flows.values()))[0])
    extra["function_key"] = "0x999999"
    flows["0x999999"] = [extra]
    evidence, _ = read_call_evidence([FIXTURES / "evidence.jsonl"])
    from revenginstr.callind_inventory import build_inventory

    with pytest.raises(ValueError, match="outside the canonical population"):
        build_inventory(population, flows, evidence)
