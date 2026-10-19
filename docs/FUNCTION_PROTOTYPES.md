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
--output hypotheses.jsonl` produces `FunctionPrototypeHypothesis/1` rows. It
uses High-P-code parameter types as provisional shapes and direct-call arity
only as a compatibility constraint. It does not infer pointer/scalar types
from argument widths, does not treat the selected call set as complete, and
marks every hypothesis `review` unless observed arity conflicts force
`conflicted`. The current confidence score is a bounded triage heuristic, not
a calibrated probability; independent audited gold and whole-program coverage
are still needed before high-confidence use.
Because hypothesis schema `/1` has no variadic marker, variadic observations
retain their fixed parameter prefix but emit `parameter_count: null` instead
of presenting the prefix as the total argument count.

`revenginstr-prototype-coverage` audits whether the evidence set covers the
program index: it checks P-code acquisition states and operation counts,
decompiler-parameter status for each indexed function, and exact direct and
indirect call-site counts against supplied flow artifacts.

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
