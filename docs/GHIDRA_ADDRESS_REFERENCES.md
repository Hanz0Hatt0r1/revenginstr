# Ghidra address-reference export

ExportGhidraAddressReferences.java records data at selected addresses and direct
references to them as REVENGINSTR.GhidraAddressReferences/1 JSONL rows. Rows
include primary-symbol and data-type metadata, reference source/type/operand,
primary status, containing-function identity, and the referencing instruction.
The exporter is read-only and operates on addresses supplied by the caller.

Run it against an existing Ghidra project:

    GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_address_references.sh \
      /path/to/project ProjectName program \
      /tmp/address-references.jsonl 00401000 00402000

Targets may use bare hexadecimal addresses, a 0x prefix, or Ghidra's DAT_
label prefix. Missing targets produce a found: false row and fail the
headless command. The runner also requires a success marker and exact output
row count, so a script failure cannot pass just because `analyzeHeadless`
returned zero. The schema is in
schemas/ghidra-address-references-v1.schema.json.
