# Ghidra field-store candidates

Export bounded High P-code STORE candidates whose destination expression contains
a caller-selected constant field offset. Functions are selected by one or more
caller-supplied name fragments. The exporter does not assign class meaning to
the offset or fragments.

The tab-separated row contract is defined by
schemas/ghidra-field-store-candidates-v1.schema.json. Cells remain strings for
compatibility with existing consumers. Constants are unsigned hexadecimal
tokens; sequence times are decimal.

Run against an already analyzed program:

    GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_field_store_candidates.sh \
      /path/to/projects project-name program-name 'name-fragment;other-fragment' \
      0x24 /tmp/field-stores.tsv

The runner uses read-only, no-analysis mode and an isolated script directory.
The exporter bounds recursive address-expression tracing and rejects cycles.
Function-name fragments and field offsets are supplied by the consumer; keep
game-specific values in that consumer repository.
