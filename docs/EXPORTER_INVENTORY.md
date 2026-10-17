# Shared exporter and runner inventory

This inventory records where reusable Ghidra export and analysis mechanisms
live and which consumer compatibility layers remain. It uses the fetched
`origin/main` snapshots checked on 2026-10-17 and refreshed after the first
same-program bounded P-code parity report:

| Repository | Snapshot |
|---|---|
| `Hanz0Hatt0r1/revenginstr` | `4db31ef8` |
| `Hanz0Hatt0r1/nevergone-recomp` | `985bf294` |
| `Hanz0Hatt0r1/nfs-shift-decompilation` | `e660406e` |

The consumer working trees have local state, so this inventory describes the
remote `main` snapshots only. Program-derived rows and invocation details stay
in their consumer repositories.

## Classification

| Capability | Canonical implementation | Nevergone boundary | NFS Shift boundary | Classification / next action |
|---|---|---|---|---|
| Portable high P-code corpus, corpus audit and foreign-project guard | `PortablePcodeCorpusExporter.java`, `revenginstr.pcode.audit`, `revenginstr.ood.foreign_guard` | `ExportMlPcodeCorpus.java` remains a legacy-format fallback; its comment records 2,000-function parity. New exports use the shared runner. | `run_shift_cross_project_pcode_probe.sh` calls the shared exporter, audit and guard; classifier transfer remains opt-in. | Canonical here, with consumer-owned format/data adapters. Keep corpus rows, labels and model configuration in each consumer. |
| One-function P-code flow and bounded forward/reverse callgraph export | `ExportFunctionPcodeFlow.java`, `ExportBoundedCallGraphPcodeFlow.java`, `ExportBoundedReverseCallGraphPcodeFlow.java`; shared TSV contract, runner and `revenginstr-export-parity` in `revenginstr` | Nevergone's single-function exporter source is byte-identical to the shared source. Its bounded local exporters retain consumer-specific traversal priorities; the shared versions accept generic priority rules. One same-program bounded forward/reverse comparison now reports byte-identical output under equivalent priority policies; details and hashes stay in the [consumer evidence report](https://github.com/Hanz0Hatt0r1/nevergone-recomp/blob/main/docs/evidence/ghidra-export-parity.md). The runner selects shared scripts when available and keeps local fallbacks. | No consumer-local flow exporters appear in the inspected NFS `origin/main` tree; its cross-project probe uses the shared portable corpus path. | Shared implementations are canonical. Keep the Nevergone compatibility fallbacks until parity coverage spans additional roots and bounds. |
| Generic address/reference and program-index export | `ExportGhidraAddressReferences.java`, `ExportGhidraAddressReferenceOwners.java`, `ExportGhidraAddressMetadata.java`, `ExportGhidraProgramIndex.java` and shared runners | `ExportAddressReferenceOwners.java` adapts shared rows to the retained Nevergone format; `run_nevergone_program_index.sh` delegates to the shared runner first. | `run_shift_global_references.sh` uses the shared address-reference exporter and a small output adapter. | Canonical here, with thin consumer adapters. Preserve consumer joins and historical file contracts at the boundary. |
| Instruction, slice, operand, scalar and compact-stream export | `ExportGhidraFunctionInstructions.java`, `ExportGhidraInstructionSlices.java`, `ExportGhidraFunctionOperands.java`, `ExportGhidraScalarUses.java`, `ExportGhidraCompactInstructionStream.java` | Shared-first runners are present for selected probes; consumer-specific joins remain local. | `run_shift_function_instructions.sh`, `run_shift_instruction_slices.sh`, `run_shift_scalar_uses.sh` and the manager compact-stream runner call generic exporters and adapt output tags. Legacy `Shift*Exporter.java` sources remain as fallbacks. | Canonical here with thin adapters; local `Shift*` exporter implementations are duplicate compatibility fallbacks pending per-format parity checks. |
| Structural stores, parameters and defined strings | `ExportGhidraFieldStoreCandidates.java`, `ExportGhidraParameterStoreField.java`, `ExportGhidraPcodeDefinedStrings.java` | `ExportPcodeDefinedStrings.java` adapts shared rows to its historical TSV. The current-frame probe delegates to the shared field-store runner when available. `ExportParameterStoreField.java` remains a full local analysis implementation. | P1/vehicle and resource exporters that consume these primitives remain title-specific. | Canonical shared extraction with a thin defined-strings wrapper; Nevergone parameter-store logic is a duplicate pending same-input parity review. |
| Receiver type, vtable and dispatch evidence | `ExportIndirectCallReceiverTypes.java`, `ExportArm32ItaniumVtableSlots.java`, `revenginstr.receiver.plan`, `revenginstr.receiver.infer` | Receiver catalogs, labels, class/vtable identities and game-specific query sets remain in Nevergone. Its pipeline calls shared planning/inference tools where the adapter contract matches. | SHIFT receiver provenance and vtable investigations remain under `tools/ghidra` and `tools/ml`; they use shared P-code tools where declared. | Generic catalog inference and table mechanics are canonical here. Raw evidence acquisition and interpretation stay consumer-specific unless a second consumer establishes the same evidence contract. |
| Family mining, classifiers, routers and frozen/drift validation | `revenginstr.family`, `revenginstr.ml`, `revenginstr.validation` | Nevergone datasets, labels, thresholds, models and frozen corpora remain local; generic calls use adapters. | The cross-project probe calls shared family/P-code/OOD tooling; SHIFT-specific weak labels and target evidence remain local. | Canonical here for algorithms and schemas; both consumers own experiment configuration and evidence. |
| Consumer semantic/runtime evidence exporters | No common contract established | Scene, action, controls, asset and runtime-capture exporters under `tools/ghidra`, `tools/ml` and `tools/android` | SHIFT address, subsystem, vehicle, renderer and runtime evidence tools | Consumer-specific by design until an independently shared schema and second consumer use exist. Do not move their labels or evidence into this repository. |

## Canonical Ghidra surface in `revenginstr`

The shared Java exporters are grouped by their output contract:

- **P-code and call/dataflow:** `PortablePcodeCorpusExporter`,
  `ExportFunctionPcodeFlow`, `ExportBoundedCallGraphPcodeFlow`,
  `ExportBoundedReverseCallGraphPcodeFlow`, `ExportGhidraCallerArgumentSubtree`,
  `ExportGhidraIndirectCallEvidence`, `ExportIndirectCallReceiverTypes`.
- **Program and address references:** `ExportGhidraProgramIndex`,
  `ExportGhidraAddressReferences`, `ExportGhidraAddressReferenceOwners`,
  `ExportGhidraAddressMetadata`.
- **Instruction and operand evidence:** `ExportGhidraFunctionInstructions`,
  `ExportGhidraInstructionSlices`, `ExportGhidraCompactInstructionStream`,
  `ExportGhidraFunctionOperands`, `ExportGhidraScalarUses`.
- **Structural evidence:** `ExportGhidraFieldStoreCandidates`,
  `ExportGhidraParameterStoreField`, `ExportGhidraPcodeDefinedStrings`.
- **Vtable support:** `ExportArm32ItaniumVtableSlots`.

The matching `scripts/run_ghidra_*.sh` entry points are canonical runners. The
Python modules listed above own portable parsing, aggregation, inference,
classification and validation; consumers retain path discovery and local joins.

## Follow-up from this snapshot

1. Expand Nevergone same-program parity coverage across additional roots and
   traversal bounds. Keep hash-only reports and invocation details in the
   consumer; retain the local bounded fallbacks until those cases are covered.
2. For NFS Shift's remaining direct `Export*` sources, record which scripts
   invoke them and add same-input parity fixtures before making any wrapper
   shared-first.
3. Keep legacy format adapters until their existing command and row contracts
   are covered. No file is marked obsolete in this first inventory because no
   caller-free proof was made.
4. Update this table in each exporter migration PR; do not include consumer
   labels, evidence rows, addresses or catalogs in the inventory.

## Status vocabulary

- **Canonical in `revenginstr`:** the reusable implementation and runner live
  here; no consumer-owned adaptation is needed for the generic contract.
- **Canonical with thin consumer wrapper:** the shared implementation is used,
  while a small adapter preserves a historical command or output format.
- **Consumer-specific by design:** the exporter depends on title-specific
  addresses, labels, runtime behavior or semantic interpretation.
- **Duplicate pending migration:** a full local implementation still exists;
  keep it until same-input parity is demonstrated.
- **Obsolete:** no current caller and replacement are both proven. No exporter
  is classified obsolete in this snapshot because caller-free proof was not
  performed.
