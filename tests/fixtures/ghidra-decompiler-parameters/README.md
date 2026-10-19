# Real Ghidra decompiler-parameter replay

Captured with Ghidra 12.1.2 and Java 21 from the small x86-32 `callsite_fixture.o`
headless project used by the function-prototype exporter replay. The fixture
contains a stored/imported `sample_add(Node *, int)` and `sample_caller(Node *)`
that passes two arguments to it. `sample-caller-flow.tsv` is the exact source
artifact referenced by `call-observations.jsonl`; the JSONL records are retained
as ordinary text so the inference pipeline can be exercised without Ghidra.
The program SHA-256 is pinned in each JSON record.
