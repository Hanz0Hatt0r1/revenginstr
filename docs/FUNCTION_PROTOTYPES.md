# Function prototype hypotheses

`FunctionPrototypeHypothesis/1` stores evidence-linked signature candidates for
one hash-pinned function. A candidate records calling convention, parameter
count and indexed parameter shapes, return shape, optional receiver index, and
a producer-supplied confidence score. Parameter and return kinds distinguish
pointers, references, scalars, aggregates, and unknowns. `candidate`, `review`,
and `conflicted` are triage states; conflicts retain reason codes and evidence.
The architecture record pins language ID, pointer width, and endianness; gold
and hypotheses must agree on it. The schema is a data contract and does not
infer signatures.

## Ghidra signature evidence

`GhidraFunctionPrototype/1` snapshots signatures already stored in an analyzed
Ghidra database, including structured parameter/return types, calling
convention, signature source, executable SHA-256, and ABI. `USER_DEFINED`,
`IMPORTED`, `ANALYSIS`, and `DEFAULT` remain distinct source labels; this
exporter does not promote a Ghidra signature to recovered truth. The read-only
runner accepts the same exact/containing function plan as the identity
exporter:

```sh
GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_function_prototypes.sh \
  /path/to/projects project-name program-name function-plan.tsv \
  function-prototypes.jsonl
```

This provides structured source evidence for later inference and adjudication.
It does not assign hypothesis confidence or infer signatures from call sites.

`revenginstr-direct-call-arguments` extracts observed argument counts and
varnode widths from resolved direct `CALL` rows in `GhidraFunctionPcodeFlow/1`
TSV files. Each row points to its exact source file hash and data row. The
observation retains call-site evidence and does not claim that all callers were
exported, turn argument widths into pointer/scalar types, or treat an observed
call shape as the callee's complete prototype. Keep inputs from one Ghidra
program per invocation.

```sh
revenginstr-direct-call-arguments caller-flow-*.tsv --program-id nfs-shift-1.0 \
  --output direct-call-arguments.jsonl
```

`FunctionPrototypeGold/1` describes one independently adjudicated function.
`complete_properties` names the top-level signature properties the reviewer
verified; `complete_parameter_indices` names parameter positions verified
individually. Other properties are unknown and do not count as mismatches.
Multiple compatible prototypes can capture ABI or source-level alternatives.
Gold evidence cannot cite the evaluated hypothesis or gold file itself.

Evaluate JSONL inputs with:

```sh
revenginstr-function-prototype-evaluate hypotheses.jsonl gold.jsonl \
  --minimum-confidence 0.95 \
  --output prototype-evaluation.json
```

The report includes high-confidence candidate compatibility, per-function
coverage, top-candidate compatibility, per-property accuracy, and conflict
rate. Property metrics use all candidates; acceptance metrics apply the stated
confidence threshold, and a conflicted function is not accepted at any
confidence. A tied top-confidence choice is conservatively counted as not
compatible for the top-candidate metric.

`tests/fixtures/function-prototype-{hypothesis,gold}/synthetic.jsonl` is an exact
synthetic replay whose gold cites a separate hash-pinned source observation.
It validates coverage and scoring behavior, not consumer accuracy. No
prototype inference engine or independently adjudicated consumer corpus is
implemented yet; those remain roadmap work.
