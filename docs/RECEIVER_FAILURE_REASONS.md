# Receiver inference failure reasons

`revenginstr-receiver-infer` keeps its existing `ReceiverInference/1` JSONL
output unchanged. Pass `--failure-reasons-output <path>` to write an optional
`ReceiverFailureReason/1` JSONL sidecar. It contains one record for each
unresolved `(source_id, call_index)` in input order and no records for resolved
queries. It does not contain class names, vtable ids, or routing decisions.

## Current reason codes

| Code | Emitted when |
|---|---|
| `receiver_not_single_pointer` | The receiver is not a single pointer and no transparent single-pointer flow supplied a type. |
| `insufficient_receiver_type_evidence` | No usable direct or transparent-flow type name is available. |
| `missing_vtable_catalog_entry` | A usable type name is present but does not map to a catalog class. |
| `mixed_receiver_candidates` | Type evidence maps to multiple classes, including a terminal name shared by multiple catalog classes. |
| `ambiguous_receiver_vtable` | One class maps to multiple receiver vtable identities. |

These reasons describe only the receiver inference stage. They do not claim
that a class or dispatch target is correct, and do not authorize target
transfer.

## Reserved for evidence-producing stages

The schema reserves these codes for future stages that can establish the
corresponding failure from explicit evidence:

- `missing_root_provenance`
- `ambiguous_phi`
- `caller_argument_propagation_gap`
- `field_load_store_propagation_gap`
- `singleton_default_instance_gap`
- `factory_return_gap`
- `nested_container_object_gap`
- `slot_ambiguity`
- `non_virtual_call_indirect`
- `linker_veneer_artifact`
- `pcode_decompiler_limitation`
- `unsupported_pattern`

The current type/catalog stage does not emit these reserved codes. Missing
evidence alone is not enough to assign a specific dataflow or toolchain cause.
