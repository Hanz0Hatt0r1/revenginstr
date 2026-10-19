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
revenginstr-direct-call-arguments caller-flow-*.tsv --program-id program-name \
  --program-sha256 <executable-sha256> \
  --output direct-call-arguments.jsonl
```

`revenginstr-prototype-callsite-check` compares those observations with
`GhidraFunctionPrototype/1` snapshots by exact callee entry. It checks arity
only: fixed signatures require an exact argument count, while variadic
signatures require at least their fixed parameter count. Results retain both
input artifact references and the Ghidra signature source. A matching call
shape is local evidence only; it does not prove that all callers were captured
or that the stored signature is correct. Use the same `program_id` in both
inputs; it must equal the Ghidra program name recorded in the prototype export.
The call observations also carry the executable SHA-256; the checker rejects
observations and prototypes pinned to different binaries.

```sh
revenginstr-prototype-callsite-check direct-call-arguments.jsonl \
  function-prototypes.jsonl --output callsite-compatibility.jsonl
```

`GhidraDecompilerParameters/1` captures the High-P-code formal symbols and
return type for selected functions. Its status records decompilation failures;
parameter rows include Ghidra's type lock and storage metadata so consumers can
separate stored information from decompiler evidence. Run it with a function
identity plan:

```sh
GHIDRA_HOME=/opt/ghidra scripts/run_ghidra_decompiler_parameters.sh \
  /path/to/projects project-name program-name plan.tsv decompiler-parameters.jsonl
```

`revenginstr-prototype-infer decompiler-parameters.jsonl call-observations.jsonl
--caller-parameter-roots caller-roots.tsv --output hypotheses.jsonl` produces
`FunctionPrototypeHypothesis/1` rows. High-P-code parameter types provide
provisional shapes; Ghidra `Undefined` types stay `unknown`. An optional
program-pinned `GhidraCallerArgumentParameterRoot/3` sidecar can propagate a
callee formal's pointer/scalar/aggregate shape to a caller formal only when
Ghidra proves the call argument is that exact formal with no defining P-code.
Propagation reaches a fixed point across direct calls, and contradictory
constraints remain `unknown` with `evidence_conflict`. Per-parameter evidence
links the decompiler record, exact call observation, and program-pinned root
record. Argument widths and constant-offset/cast roots do not supply types.
The selected call set is not treated as complete, and hypotheses stay `review`
unless arity or type conflicts force `conflicted`. Confidence remains a bounded
triage heuristic, not a calibrated probability; independent audited gold is
still needed before high-confidence use.
Because hypothesis schema `/1` has no variadic marker, variadic observations
retain their fixed parameter prefix but emit `parameter_count: null` instead
of presenting the prefix as the total argument count.

`revenginstr-prototype-coverage` audits whether the evidence set covers the
program index: it checks P-code acquisition states and operation counts,
decompiler-parameter status for each indexed function, and exact direct and
indirect call-site counts against supplied flow artifacts.

`tests/fixtures/ghidra-untyped-prototype/` is a real Ghidra 12.1.2 replay of a
stripped x86 object with no DWARF. It demonstrates default Ghidra analysis
recovering a pointer formal in one function and an exact caller-parameter root
carrying that pointer shape into a second function whose original type is
`undefined4`. Its source-backed `FunctionPrototypeGold/1` covers two functions:
parameter count and parameter shapes are both 2/2 correct, while return shape
is 1/2 because `mystery_caller` still has an unknown return. At the default
0.95 threshold neither candidate is accepted. Evaluation v2 reports this as
50% return-shape coverage and 100% accuracy among the one known return; it keeps
the unknown return visible as an abstention. This is a small source-adjudicated
replay, not an audited consumer corpus or confidence-calibration set. The
fixture also includes a full program capture-coverage report.

```sh
revenginstr-prototype-coverage functions.tsv.gz acquisition.jsonl \
  decompiler-parameters.jsonl direct-call-arguments.jsonl \
  indirect-call-evidence.jsonl flow.tsv --output coverage.json
```

`FunctionPrototypeEvidenceCoverage/1` is complete only when every indexed
function has the expected acquisition and parameter result, batch operation
counts match the P-code flows, and all direct/indirect call-site observations
match those flows. This is an artifact-coverage statement; it does not say that
the prototypes are correct, that an unresolved direct call has a target, or
that an indirect call target was resolved. The v1 program index has no in-band
binary identity, so supply it from the same Ghidra program used for the other
inputs; the report hashes the index artifact.

`FunctionPrototypeGold/1` describes one independently adjudicated function.
`complete_properties` names the top-level signature properties the reviewer
verified; `complete_parameter_indices` names parameter positions verified
individually. Other properties are unknown and do not count as mismatches.
Multiple compatible prototypes can capture ABI or source-level alternatives.
Gold evidence cannot cite the evaluated hypothesis or gold file itself.

Evaluate JSONL inputs with:

```sh
revenginstr-function-prototype-evaluate hypotheses.jsonl gold.jsonl \
  --format-version 2 \
  --minimum-confidence 0.95 \
  --output prototype-evaluation.json
```

The report includes high-confidence candidate compatibility, per-function
coverage, top-candidate compatibility, per-property accuracy, and conflict
rate. Property metrics use all candidates; acceptance metrics apply the stated
confidence threshold, and a conflicted function is not accepted at any
confidence. Evaluation v2 also reports per-property unknown predictions,
coverage, and accuracy among known predictions. The default v1 report remains
available for existing consumers. A tied top-confidence choice is
conservatively counted as not compatible for the top-candidate metric.

`tests/fixtures/function-prototype-{hypothesis,gold}/synthetic.jsonl` is an exact
synthetic replay whose gold cites a separate hash-pinned source observation.
It validates evaluator behavior, not consumer accuracy. The inference engine
and source-backed micro-gold replay exist; a broader audited consumer corpus and
confidence calibration remain roadmap work.
