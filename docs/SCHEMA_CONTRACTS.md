# Stable schema contracts

This page is the index and compatibility policy for the versioned formats in
`schemas/`. The linked JSON Schema is authoritative for field types, required
and optional fields, conditional requirements, enumerations, bounds, and
unknown-property behavior. Format-specific prose below records the wire form,
normalization, provenance, ordering, and failure rules that JSON Schema cannot
express. Exporter-specific invocation and examples remain in the linked Ghidra
pages.

## Compatibility rules

- The `/1` in a `format` value (or the versioned schema filename where a legacy
  TSV row has no in-band `format`) identifies the contract generation. A
  breaking field, meaning, encoding, or ordering change requires a new `/2`
  contract and schema; do not silently relabel existing consumer artifacts.
- `required` lists mandatory fields. A declared property omitted from `required`
  is optional unless an `if`/`then`, `oneOf`, or referenced definition adds a
  conditional requirement. `additionalProperties` applies at each object level:
  `false` rejects unknown keys; an omitted or `true` value permits them. Readers
  of extensible objects must ignore unknown optional fields.
- JSONL is UTF-8, one JSON object per non-empty line. TSV is UTF-8, has the
  documented fixed header and column order, and represents every cell as text;
  numeric-looking TSV values remain strings on the wire. Gzip changes storage,
  not the row contract. TSV schemas describe a decoded row object while keeping
  its cell types as strings.
- Addresses and names are evidence from one selected Ghidra program, not
  globally normalized identities. Preserve their spelling and join only within
  the same program provenance. `id`, `source_id`, `plan_id`, and similar keys
  are opaque consumer join keys; never treat them as model features by default.
- For request-driven exporters, caller request order is preserved when stated
  by the exporter page. Rows discovered within a request follow Ghidra iterator
  or P-code order. That order is not guaranteed across Ghidra versions; compare
  keyed rows for parity unless the format page explicitly promises order.
  JSON object key order is not semantic.
- Exporters are read-only and expect an already analyzed program. Invalid input,
  malformed rows, missing required targets, or headless failures return a
  non-zero status. Some targeted exporters also emit an explicit `found: false`
  row before failing; empty successful result sets are documented per exporter.
- Program-specific labels, addresses, catalogs, binaries, and semantic
  interpretations stay in consumer repositories. A shared schema describes
  evidence shape, not semantic correctness.

## Portable analysis, inference, and validation

| Format and schema | Wire / field contract | Normalization, provenance, ordering, failure |
|---|---|---|
| [`PcodeCorpus/1`](../schemas/pcode-corpus-v1.schema.json) | JSONL; a failed decompile requires status and may include `error`; successful records require `metrics` and `model_text`. | `program`, `source_entry`, and `source_name` are join metadata. `model_text` is the sanitized portable operation view; the corpus exporter excludes program/function identity and addresses from it. Corpus order follows exporter function traversal. A decompile failure is represented as a record, not silently dropped. The synthetic payload fixture is `tests/fixtures/pcode-corpus/synthetic.jsonl`. |
| [`CallGraphMetrics/1`](../schemas/callgraph-metrics-v1.schema.json) | JSONL object; metrics are numeric or null. | `id` and `source_entry` identify the consumer's source record. Metrics are structural callgraph counts, not labels. Aggregation emits records in corpus order; consumers join by `id`. |
| [`PcodeAudit/1`](../schemas/pcode-audit-v1.schema.json) | JSON report; `transfer` is null unless classified rows were supplied. | Summarizes corpus formats, decompile status, model-text leakage checks and emitted-op quantiles. The optional transfer section has no semantic labels and explicitly describes cross-project/OOD interpretation. |
| [`SelectiveClassifier/1` manifest](../schemas/selective-classifier-v1.schema.json) and [prediction rows](../schemas/selective-classifier-prediction-v1.schema.json) | JSON manifest plus OOF/inference JSONL rows; OOF-only labels and family ids are optional on prediction rows, and probabilities may be omitted by inference. | Uses only portable P-code operations as model input. Calibration and OOD thresholds are family-grouped; manifest leakage policy records excluded identities and labels. |
| [`EvidenceSelectiveClassifier/1` manifest](../schemas/evidence-selective-classifier-v1.schema.json) and [prediction rows](../schemas/evidence-selective-classifier-prediction-v1.schema.json) | JSON manifest plus OOF/inference JSONL rows; rows add evidence token count and whether external evidence was present. | Extends the portable P-code representation with bucketed, project-neutral numeric evidence. The manifest records the evidence digest/count and explicitly excludes receiver class names and vtable identities. |
| [`AcceptErrorRouter/1` manifest](../schemas/accept-error-router-v1.schema.json), [crossfit scores](../schemas/accept-error-router-crossfit-score-v1.schema.json), and [prediction extension](../schemas/accept-error-router-prediction-v1.schema.json) | JSON manifest plus crossfit and inference JSONL rows. The inference contract validates router-added fields and permits original classifier fields through unchanged. | Trains on family-grouped crossfit legacy accepts. At inference, it only downgrades `accept` to `escalate`; other actions and the predicted class are preserved. Crossfit scores are calibration evidence, not target labels for inference. |
| [`Evidence/1`](../schemas/evidence-v1.schema.json) | JSONL; `features` accepts numeric and boolean values only. | Feature keys/values are project-neutral summaries. Keep raw identities, labels, and addresses outside `features`. Aggregation sorts output ids and feature keys; unmatched evidence is counted and omitted. Conflicting physical identities in the trace fail closed. |
| [`FunctionFamilies/1` rows](../schemas/function-families-v1.schema.json) and [manifest](../schemas/function-families-manifest-v1.schema.json) | JSONL rows keyed by `id`, plus one JSON manifest. | Rows sort by id; family ids derive from the minimum portable-P-code SHA-256 in each connected component. Names, addresses, and P-code headers are excluded from family features. The manifest records thresholds/profile and a local dataset path; custom `output_format` values require a consumer-owned schema. |
| [`ForeignGuard/1` summary](../schemas/foreign-guard-v1.schema.json) and [row extension](../schemas/foreign-guard-row-v1.schema.json) | JSON summary plus input-row-preserving JSONL output. | The summary sorts action/reason maps. Each output row retains all input fields and adds the required guard fields; only `accept` may become `review`. The guard uses no target labels and never promotes actions. |
| [`ReceiverPlan/1`](../schemas/receiver-plan-v1.schema.json) | Headered TSV; all cells are strings and `expected_calls` is initially empty. | `source_id` is `program:source_entry`. Rows sort by numeric hexadecimal entry, with non-hex entries after them in lexical order. The selected program filter and trace population are invocation provenance; empty/invalid plans fail. |
| [`GhidraIndirectReceiverType/1`](../schemas/ghidra-indirect-receiver-type-v1.schema.json) | Headered TSV; all cells, including counts and JSON-encoded flow arrays, are strings. | `source_id` is a caller-supplied join key; function/call metadata is from the selected program. Rows follow selected-function and High-P-code call order. Empty/unknown receiver facts use the exporter’s explicit string sentinels. |
| [`ReceiverInference/1`](../schemas/receiver-inference-v1.schema.json) | JSONL; all schema properties are required, with null permitted for unavailable observations. | Joins generic receiver observations to a consumer-owned catalog. Class/vtable identities are consumer evidence. The schema fixes `affects_routing` and all transfer permissions to false; this format does not authorize target transfer. Input call order is retained; ambiguity is a status, not an exception. |
| [`ReceiverFailureReason/1`](../schemas/receiver-failure-reason-v1.schema.json) | Optional JSONL sidecar; one record per unresolved receiver query, with exactly one primary reason code. | Joins by `source_id` and `call_index`; records use input order and preserve the inference status. Current codes and reserved-code semantics are documented in [Receiver failure reasons](RECEIVER_FAILURE_REASONS.md). |
| [`ReceiverCandidateAssessment/1`](../schemas/receiver-candidate-assessment-v1.schema.json) | Optional JSONL sidecar; one record per receiver query. | Joins by `source_id` and `call_index`; reports known candidate convergence separately from unresolved typed sources. Multiple classes are compatible only when the consumer catalog supplies one shared `receiver_compatibility_group_id`. It does not change `ReceiverInference/1` or authorize routing. See [candidate assessment](RECEIVER_CANDIDATE_ASSESSMENT.md). |
| [`ReceiverCandidateEvidence/1`](../schemas/receiver-candidate-evidence-v1.schema.json) | JSONL; one evidence vector per receiver candidate. | Seven evidence dimensions retain separate supported/contradicted/unknown/not-applicable states, evidence classes, and source-record provenance. No aggregate score or decision is defined. Repeated provenance references identify correlated evidence. See [candidate evidence vector](RECEIVER_CANDIDATE_EVIDENCE.md). |
| [`ReceiverProvenanceGraph/1`](../schemas/receiver-provenance-graph-v1.schema.json) | JSONL; one graph per record, with graph-local nodes and directed edges. | Every edge requires an evidence class and one or more opaque source-format/source-id references. Shared references identify correlated support; addresses, labels, and class catalogs are not graph features. Duplicate ids and dangling endpoints fail the generic reference check. See [receiver provenance graph](RECEIVER_PROVENANCE_GRAPH.md). |
| [`FrozenValidation/1`](../schemas/frozen-validation-v1.schema.json) | JSON manifest; nested trace/output records carry row counts and SHA-256 digests. | Selection uses stable identity hashing and a caller-owned salt. Source, eligibility, exclusion, frozen-corpus, and trace hashes make provenance replayable. Selection is deterministic for the same inputs/configuration; existing manifests are not overwritten unless explicitly requested. |
| [`DriftAudit/1`](../schemas/drift-audit-v1.schema.json) | JSON diagnostic report; selected nested report objects are extensible. | Reports reference and frozen populations, but have `labels_available: false`; severity is diagnostic only, never accuracy. Distributions are normalized by the audit. Evidence-key coverage and counts retain input provenance through the report, not raw rows. |

## Ghidra export rows

Every linked row schema fixes required/optional fields and types. Addresses,
symbols, signatures, disassembly, and P-code observations are sourced from the
selected program; schemas without an in-band `program` field rely on the
invocation/output manifest for program provenance. The format-specific pages
below define target parsing, sentinel values, and empty/missing-target behavior.

| Export family | Contract |
|---|---|
| Address metadata | [`GhidraAddressMetadata/1`](../schemas/ghidra-address-metadata-v1.schema.json) · [details](GHIDRA_ADDRESS_METADATA.md). One row per requested address, in request order; the raw word uses the program endianness. |
| Address references | [`GhidraAddressReferences/1`](../schemas/ghidra-address-references-v1.schema.json) · [details](GHIDRA_ADDRESS_REFERENCES.md). Request order is retained; an unresolved target is explicit and causes the command to fail. |
| Address reference owners | [`GhidraAddressReferenceOwner/1`](../schemas/ghidra-address-reference-owners-v1.schema.json) · [details](GHIDRA_ADDRESS_REFERENCE_OWNERS.md). Headered TSV; a target with no references has one row with `-` reference cells. |
| ARM32 Itanium vtable slots | [`GhidraArm32ItaniumVtableSlots/1`](../schemas/ghidra-arm32-itanium-vtable-slots-v1.schema.json) · [details](GHIDRA_VTABLE_SLOTS.md). Headered gzip TSV; vtables sort by symbol address and slots ascend by offset, stopping at the first invalid/non-function pointer. |
| Caller argument plan | [`GhidraCallerArgumentSubtreePlan/1`](../schemas/ghidra-caller-argument-subtree-plan-v1.schema.json) · [details](ghidra-caller-argument-subtree.md). Exactly three TSV cells; `plan_id` is opaque consumer metadata. |
| Caller argument subtree | [`GhidraCallerArgumentSubtree/1`](../schemas/ghidra-caller-argument-subtree-v1.schema.json) · [details](ghidra-caller-argument-subtree.md). Headered TSV with summary and bounded tree rows; depth/node/caller limits and per-caller statuses are explicit. |
| Caller argument parameter roots | [`GhidraCallerArgumentParameterRoot/1`](../schemas/ghidra-caller-argument-parameter-root-v1.schema.json) · [details](ghidra-caller-argument-subtree.md). Optional headered TSV sidecar; only exact caller-formal roots are emitted to support bounded recursive propagation. |
| Compact instruction stream | [`GhidraCompactInstructionStream/1`](../schemas/ghidra-compact-instruction-stream-v1.schema.json) · [details](GHIDRA_COMPACT_INSTRUCTION_STREAM.md). JSONL starts with one program header, then decoded instructions in address order; gzip is transport only. |
| Field-store candidates | [`GhidraFieldStoreCandidates/1`](../schemas/ghidra-field-store-candidates-v1.schema.json) · [details](GHIDRA_FIELD_STORE_CANDIDATES.md). Headered TSV; sequence times and offsets remain textual numbers/hex tokens. Caller-supplied filters have no class semantics. |
| Function identity plan | [`GhidraFunctionIdentitiesPlan/1`](../schemas/ghidra-function-identities-plan-v1.schema.json) · [details](ghidra-function-identities.md). Exactly `plan_id`, requested address, and resolution policy; request order is retained. |
| Function identity | [`GhidraFunctionIdentity/1`](../schemas/ghidra-function-identities-v1.schema.json) · [details](ghidra-function-identities.md). Headered TSV; rows follow plan order. An invalid plan or unresolved function aborts the command rather than emitting a partial identity row. |
| Function instructions | [`GhidraFunctionInstructions/1`](../schemas/ghidra-function-instructions-v1.schema.json) · [details](GHIDRA_FUNCTION_INSTRUCTIONS.md). One JSONL row per requested function; instruction/reference/P-code arrays follow the selected function’s program order. Missing functions are explicit and fail the command. |
| Function operands | [`GhidraFunctionOperand/1`](../schemas/ghidra-function-operands-v1.schema.json) · [details](GHIDRA_FUNCTION_OPERANDS.md). JSONL rows follow function, instruction, then operand order; a function with no matching numeric operand yields no rows. |
| Function High P-code flow | [`GhidraFunctionPcodeFlow/1`](../schemas/ghidra-function-pcode-flow-v1.schema.json) · [details](GHIDRA_FUNCTION_PCODE_FLOW.md). Headered TSV; operation rows follow High-P-code sequence order; TSV cells are strings. |
| Indirect-call evidence | [`GhidraIndirectCallEvidence/1`](../schemas/ghidra-indirect-call-evidence-v1.schema.json) · [details](GHIDRA_INDIRECT_CALL_EVIDENCE.md). One JSONL row per `CALLIND` in P-code order; no indirect calls yields an empty file. |
| Instruction slices | [`GhidraInstructionSlice/1`](../schemas/ghidra-instruction-slice-v1.schema.json) · [details](GHIDRA_INSTRUCTION_SLICES.md). Request order is retained; bounds and empty/missing instruction facts are explicit. |
| Parameter-to-field stores | [`GhidraParameterStoreField/1`](../schemas/ghidra-parameter-store-field-v1.schema.json) · [details](GHIDRA_PARAMETER_STORE_FIELD.md). Headered TSV; parameter indices are zero-based decimal strings and offsets are signed hexadecimal strings. |
| Parameter-rooted field loads | [`GhidraParameterLoadField/1`](../schemas/ghidra-parameter-load-field-v1.schema.json) · [details](GHIDRA_PARAMETER_LOAD_FIELD.md). Optional headered TSV sidecar from the parameter-store exporter; each row identifies a `LOAD` rooted at one formal parameter and retains the result token for later exact joins. |
| P-code defined strings | [`GhidraPcodeDefinedString/1`](../schemas/ghidra-pcode-defined-strings-v1.schema.json) · [details](GHIDRA_PCODE_DEFINED_STRINGS.md). Headered TSV; resolves only existing defined String data, with text UTF-8 encoded as Base64. |
| Scalar uses | [`GhidraScalarUses/1`](../schemas/ghidra-scalar-uses-v1.schema.json) · [details](GHIDRA_SCALAR_USES.md). JSONL in program instruction order; exact unsigned scalar matches are candidates, not semantic proof. |
| Program index: functions | [`GhidraProgramIndex.Functions/1`](../schemas/ghidra-program-index-functions-v1.schema.json) · [details](GHIDRA_PROGRAM_INDEX.md). Headered gzip TSV in Ghidra function iteration order. |
| Program index: symbols | [`GhidraProgramIndex.Symbols/1`](../schemas/ghidra-program-index-symbols-v1.schema.json) · [details](GHIDRA_PROGRAM_INDEX.md). Headered gzip TSV in Ghidra symbol iteration order. |
| Program index: strings | [`GhidraProgramIndex.Strings/1`](../schemas/ghidra-program-index-strings-v1.schema.json) · [details](GHIDRA_PROGRAM_INDEX.md). Defined strings only, in listing order; UTF-8 bytes are Base64 and `length` is Java UTF-16 code units. |
| Program index: xrefs | [`GhidraProgramIndex.Xrefs/1`](../schemas/ghidra-program-index-xrefs-v1.schema.json) · [details](GHIDRA_PROGRAM_INDEX.md). Headered gzip TSV in Ghidra reference iterator order. |
| Program index: calls | [`GhidraProgramIndex.Calls/1`](../schemas/ghidra-program-index-calls-v1.schema.json) · [details](GHIDRA_PROGRAM_INDEX.md). Resolved direct calls only; relative order follows the xref iterator. |

## Validation and benchmark records

These reports are data products, not semantic labels. They carry hashes and
configuration identity where defined by their schema; do not remove or
recalculate provenance fields when retaining an experiment.

| Format | Contract |
|---|---|
| [`BenchmarkManifest/1`](../schemas/benchmark-manifest-v1.schema.json) | Pinned inputs, toolchain, schema versions, configs, stages and gates. Input artifacts require SHA-256; output hashes are produced by execution. See [benchmark workflow](BENCHMARKS.md). |
| [`BenchmarkSummary/1`](../schemas/benchmark-summary-v1.schema.json) | Execution result with artifact hashes, stage status, metrics, projections, and gate failures. Stage and projection arrays retain manifest order. See [benchmark workflow](BENCHMARKS.md). |
| [`BenchmarkDelta/1`](../schemas/benchmark-delta-v1.schema.json) | Baseline/candidate numeric metric comparison keyed by benchmark dataset/split/family identity. Missing/non-numeric metrics remain null; delta is candidate minus baseline. |
| [`DeterminismAudit/1`](../schemas/determinism-audit-v1.schema.json) | Two replay results and stable difference paths; duration and peak RSS are deliberately ignored by the audit. Failed runs are reported with status/error, not treated as deterministic success. |
| [`SelectiveThresholdSweep/1`](../schemas/selective-threshold-sweep-v1.schema.json) · [usage](SELECTIVE_THRESHOLD_SWEEP.md) | Per-predicted-class precision/coverage thresholds over hashed family-grouped OOF predictions; audit only, with no change to a trained model or inference policy. |
| [`SelectiveThresholdEvaluation/1`](../schemas/selective-threshold-evaluation-v1.schema.json) · [usage](SELECTIVE_THRESHOLD_EVALUATION.md) | Applies OOF-selected per-class thresholds to a family-disjoint evaluation set and reports classwise reliability bins, Brier score, ECE, and held-out precision/coverage. |
| [`ClassifierErrorBuckets/1`](../schemas/classifier-error-buckets-v1.schema.json) · [usage](CLASSIFIER_ERROR_BUCKETS.md) | Groups errors from the exact hashed family-disjoint evaluation file by truth/prediction pair, route action, and confidence; no row identities are emitted. |
| [`GhidraExportParity/1`](../schemas/ghidra-export-parity-v1.schema.json) · [usage](GHIDRA_EXPORT_PARITY.md) | Hashes and row counts for two TSVs, decoded header/row equality in order, and the first mismatch index. Record values and input paths are omitted. |

## Known schema coverage gaps

All versioned schemas currently published in `schemas/` are linked above and
validated against representative generated artifacts. New stable formats must
be added to this index and contract test in the same change that publishes
their schema. Consumer-specific outputs remain consumer-owned.
