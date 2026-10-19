# Program-wide CALLIND inventory

`revenginstr-callind-inventory` reconciles a hash-linked function population
with `GhidraFunctionPcodeFlow/1` TSV and optional
`GhidraIndirectCallEvidence/1` or `/2` JSONL. V2 rows pin the executable
SHA-256 and ABI. It emits one function record for every
population member and one site record for every observed `CALLIND`.

The normalized input `CallindPopulation/1` must contain one row per function
in a single program. `acquisition_state` is the state of the High-P-code flow
export: use `complete` only after the Ghidra runner reports its completion
marker; preserve `truncated`, `no_pcode`, `decompile_failed`, `export_failed`,
`not_exported`, or `unknown` explicitly. `expected_callind_count` is an
optional count from a canonical P-code population, not receiver-query counts.
`canonical_source` pins the source artifact and row used to make that population
record. `canonical_truncated` is metadata about that canonical source and does
not itself say that the flow export is truncated.

```sh
revenginstr-callind-inventory population.jsonl inventory.jsonl \
  --pcode-flow-dir flow-tsv/ \
  --indirect-call-evidence-dir callind-jsonl/ \
  --summary inventory-summary.json
```

The P-code flow TSV does not carry a program identifier, so each run accepts a
population for exactly one `program_id`. Extra flow functions, contradictory
acquisition states, duplicate operation keys, duplicate evidence sites, and
evidence rows without an exact site match fail closed. A complete population
entry without a flow is emitted as `export_missing`. Missing expression evidence
does not drop a `CALLIND` site; it sets `expression_status` to `missing`.

To acquire a bounded function set in one Ghidra process, first use
[`run_ghidra_pcode_flow_batch.sh`](GHIDRA_FUNCTION_PCODE_FLOW.md) to produce the
standard flow TSV, target-expression JSONL, and per-function acquisition JSONL.
The consumer adapter then joins those acquisition states and its canonical
call-count source into `CallindPopulation/1`.

Addresses are joined after hexadecimal normalization, preserving an explicit
address-space prefix. The site key is `(program_id, function_entry,
call_address, call_time)`. `pcode_source` and
`indirect_call_evidence_source` pin artifact hashes and record indexes. Every
function row also links back to its canonical source record and the population
manifest that carried it.

Count reconciliation distinguishes exact `matched`/`mismatch`, a
`lower_bound` from a truncated flow, and acquisition failures. The summary
reports the expected and observed totals and enumerates every input artifact.
Do not interpret `CALLIND` as a virtual call. The initial inventory labels all
sites `unknown`; a future evidence-backed review may set `virtual_candidate` or
`other_indirect_candidate` with a documented basis. The inventory does not
infer receiver classes, vtables, slots, or targets.

`CallindPopulation/1` is the consumer adapter boundary. A consumer may map its
own frozen corpus or function index into this normalized input, preserving its
original format, file hash, and row index in `canonical_source`; generic
RevEngInstr code does not depend on consumer-specific dataset formats.
