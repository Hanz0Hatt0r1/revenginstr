from __future__ import annotations

import json
from pathlib import Path

from revenginstr.validation.frozen import freeze_validation


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")


def _row(index: int) -> dict:
    entry = f"{0x500000 + index * 0x10:08x}"
    return {
        "format": "REVENGINSTR.PcodeCorpus/1",
        "program": "consumer.bin",
        "source_entry": entry,
        "source_name": f"FUN_{entry}",
        "external": False,
        "decompile_status": "ok",
        "metrics": {"emitted_ops": 1, "truncated": False},
        "model_text": "ARCH=X8632\nENDIAN=LE\nPTR_SIZE=4\no0 RETURN\n",
    }


def test_eligibility_trace_keeps_consumer_semantics_out_of_core(tmp_path: Path) -> None:
    source = tmp_path / "source.jsonl"
    eligible = tmp_path / "eligible.jsonl"
    excluded = tmp_path / "excluded.jsonl"
    output = tmp_path / "frozen"
    rows = [_row(index) for index in range(10)]
    _write_jsonl(source, rows)
    _write_jsonl(
        eligible,
        [
            {
                "program": "consumer.bin",
                "source_entry": rows[index]["source_entry"],
                "consumer_reason": "project-owned internal-origin policy",
            }
            for index in range(2, 8)
        ],
    )
    _write_jsonl(
        excluded,
        [{"program": "consumer.bin", "source_entry": rows[3]["source_entry"]}],
    )

    manifest = freeze_validation(
        source,
        output,
        eligible_traces=[eligible],
        exclude_traces=[excluded],
        limit=4,
        tag="eligible-smoke",
    )
    frozen = [json.loads(line) for line in (output / "corpus.jsonl").read_text().splitlines()]
    selected_entries = {row["source_entry"] for row in frozen}
    allowed_entries = {rows[index]["source_entry"] for index in range(2, 8)}

    assert len(frozen) == 4
    assert selected_entries <= allowed_entries
    assert rows[3]["source_entry"] not in selected_entries
    assert manifest["source_corpus"]["eligibility_removed"] == 4
    assert manifest["source_corpus"]["excluded_overlap"] == 1
    assert manifest["eligibility_traces"][0]["sha256"]
    assert manifest["exclusion_traces"][0]["sha256"]
