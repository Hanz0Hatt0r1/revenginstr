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
