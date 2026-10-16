from __future__ import annotations

import csv
import json
from pathlib import Path

from revenginstr.evidence.callgraph import extract
from revenginstr.receiver.plan import build_plan


def write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def test_callgraph_metrics_are_project_neutral(tmp_path: Path) -> None:
    corpus = tmp_path / "corpus.jsonl"
    functions = tmp_path / "functions.tsv"
    calls = tmp_path / "calls.tsv"
    write_jsonl(corpus, [{
        "id": "sample:1000", "program": "sample", "source_entry": "1000",
        "metrics": {"calls": 3, "indirect_calls": 1},
    }])
    functions.write_text(
        "entry\tis_external\n1000\tfalse\n2000\tfalse\n3000\ttrue\n",
        encoding="utf-8",
    )
    calls.write_text(
        "caller_entry\tcall_site\tcallee_entry\n"
        "1000\t1010\t2000\n1000\t1020\t3000\n",
        encoding="utf-8",
    )
    rows = extract(corpus, functions, calls)
    assert len(rows) == 1
    assert rows[0]["format"] == "REVENGINSTR.CallGraphMetrics/1"
    metrics = rows[0]["metrics"]
    assert metrics["fan_out"] == 2
    assert metrics["internal_call_site_count"] == 1
    assert metrics["external_call_site_count"] == 1
    assert metrics["corpus_direct_call_count"] == 2
    assert metrics["resolved_call_ratio_proxy"] == 2 / 3


def test_receiver_plan_supports_any_program(tmp_path: Path) -> None:
    trace = tmp_path / "trace.jsonl"
    write_jsonl(trace, [
        {"program": "a.exe", "source_entry": "2000"},
        {"program": "b.so", "source_entry": "3000"},
        {"program": "a.exe", "source_entry": "1000"},
    ])
    selected, programs = build_plan(trace, "a.exe")
    assert programs == {"a.exe": 2, "b.so": 1}
    assert selected == [("a.exe:1000", "1000"), ("a.exe:2000", "2000")]


def test_receiver_exporter_is_generic() -> None:
    root = Path(__file__).resolve().parents[1]
    text = (root / "ghidra/ExportIndirectCallReceiverTypes.java").read_text(encoding="utf-8")
    assert 'REVENGINSTR.GhidraIndirectReceiverType/1' in text
    assert "CALLIND" in text
    assert "MAX_FLOW_DEPTH = 4" in text
    assert "Nevergone" not in text
    assert "SHIFT" not in text
