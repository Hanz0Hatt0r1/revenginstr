# Real Ghidra decompiler-parameter replay

Captured with Ghidra 12.1.2 and Java 21 from the small x86-32 `callsite_fixture.o`
headless project used by the function-prototype exporter replay. The fixture
contains a stored/imported `sample_add(Node *, int)` and `sample_caller(Node *)`
that passes two arguments to it. The full-program files include Ghidra's
two-function index, batch acquisition sidecar, all 12 P-code operations,
direct-call observations, and an empty indirect-call sidecar. `flow.tsv` and
`whole-program-flow.tsv` both come from the same binary; the former is the exact
source artifact referenced by `call-observations.jsonl`, and the latter backs
`full-call-observations.jsonl`. The program SHA-256 is pinned in each JSON
record. These text fixtures let inference and coverage run without Ghidra.
