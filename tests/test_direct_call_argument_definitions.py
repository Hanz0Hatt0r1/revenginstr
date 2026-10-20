from __future__ import annotations

import csv
import hashlib
import json
from collections import Counter
from pathlib import Path

from jsonschema import Draft202012Validator
import pytest

from revenginstr.direct_call_argument_definitions import (
    _jsonl,
    resolve_call_argument_definitions,
)

ROOT = Path(__file__).resolve().parents[1]
REPLAY = ROOT / (
    "docs/evidence/semantic-program-graph-v4/"
    "nevergone-runtime-call-arguments-20261020"
)
RUNTIME = ROOT / "docs/evidence/runtime-static-correlation-v1/nevergone-device-runtime-20261019"
FLOW_PATHS = [
    RUNTIME / "LoadGameLevels.pcode-flow.tsv",
    RUNTIME / "CCFileUtilsAndroid-getFileData.pcode-flow.tsv",
]


def test_nevergone_call_argument_definitions_are_exact_and_hash_pinned() -> None:
    observations_path = REPLAY / "call-arguments.jsonl"
    output_path = REPLAY / "argument-definitions.jsonl"
    observations, observations_sha256 = _jsonl(observations_path)
    rows = [json.loads(line) for line in output_path.read_text(encoding="utf-8").splitlines()]
    rebuilt = resolve_call_argument_definitions(
        observations,
        observations_sha256=observations_sha256,
        pcode_paths=FLOW_PATHS,
    )
    rebuilt_bytes = "".join(json.dumps(row, sort_keys=True) + "\n" for row in rebuilt).encode()
    assert rebuilt_bytes == output_path.read_bytes()

    schema = json.loads(
        (ROOT / "schemas/direct-call-argument-definition-v1.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    for row in rows:
        validator.validate(row)

    counts = Counter(row["resolution_state"] for row in rows)
    assert len(rows) == 70
    assert counts == {"exact_definition": 56, "non_definition_token": 14}
    flow_rows = {}
    for path in FLOW_PATHS:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        with path.open(encoding="utf-8", newline="") as handle:
            flow_rows[digest] = list(csv.DictReader(handle, delimiter="\t"))
    for row in rows:
        if row["resolution_state"] != "exact_definition":
            assert row["definition_evidence_refs"] == []
            continue
        reference = row["definition_evidence_refs"][0]
        source = flow_rows[reference["artifact_sha256"]][reference["record_index"] - 1]
        assert source["function_entry"] == row["caller_entry"]
        assert source["op_address"] == row["value_token"].split(":")[1]
        assert source["op_time"] == row["value_token"].split(":")[2]
        assert source["output"] == row["value_token"]

    mismatched = [dict(row) for row in observations]
    mismatched[0] = {**mismatched[0], "call_address": "ffffffff"}
    with pytest.raises(ValueError, match="source P-code row does not match observation"):
        resolve_call_argument_definitions(
            mismatched,
            observations_sha256=observations_sha256,
            pcode_paths=FLOW_PATHS,
        )
