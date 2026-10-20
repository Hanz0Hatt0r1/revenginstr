# Nevergone direct-call arguments in SemanticProgramGraph/4

This replay attaches existing `DirectCallArgumentObservation/1` rows to the
hash-pinned Nevergone runtime graph. The observations come from the two
Ghidra P-code TSVs for `GameLevels::LoadGameLevels` and
`CCFileUtilsAndroid::getFileData`; each row retains the original P-code file
hash and record index.

Rebuild the observations and graph from the repository root:

```sh
PYTHONPATH=src python -m revenginstr.prototype_callsite_observations \
  docs/evidence/runtime-static-correlation-v1/nevergone-device-runtime-20261019/LoadGameLevels.pcode-flow.tsv \
  docs/evidence/runtime-static-correlation-v1/nevergone-device-runtime-20261019/CCFileUtilsAndroid-getFileData.pcode-flow.tsv \
  --program-id nevergone-1.0.9-armv7-libcocos2dcpp \
  --program-sha256 94b1ef6a9469e261183ac08199c5b0eb65c0c40b81918ca097bd32920828eb5e \
  --output docs/evidence/semantic-program-graph-v4/nevergone-runtime-call-arguments-20261020/call-arguments.jsonl

PYTHONPATH=src python -m revenginstr.direct_call_argument_definitions \
  docs/evidence/semantic-program-graph-v4/nevergone-runtime-call-arguments-20261020/call-arguments.jsonl \
  docs/evidence/runtime-static-correlation-v1/nevergone-device-runtime-20261019/LoadGameLevels.pcode-flow.tsv \
  docs/evidence/runtime-static-correlation-v1/nevergone-device-runtime-20261019/CCFileUtilsAndroid-getFileData.pcode-flow.tsv \
  --output docs/evidence/semantic-program-graph-v4/nevergone-runtime-call-arguments-20261020/argument-definitions.jsonl

PYTHONPATH=src python -m revenginstr.direct_call_argument_traces \
  docs/evidence/semantic-program-graph-v4/nevergone-runtime-call-arguments-20261020/call-arguments.jsonl \
  docs/evidence/semantic-program-graph-v4/nevergone-runtime-call-arguments-20261020/argument-definitions.jsonl \
  docs/evidence/runtime-static-correlation-v1/nevergone-device-runtime-20261019/LoadGameLevels.pcode-flow.tsv \
  docs/evidence/runtime-static-correlation-v1/nevergone-device-runtime-20261019/CCFileUtilsAndroid-getFileData.pcode-flow.tsv \
  --output docs/evidence/semantic-program-graph-v4/nevergone-runtime-call-arguments-20261020/argument-operand-traces.jsonl

PYTHONPATH=src python -m revenginstr.semantic_program_graph \
  docs/evidence/semantic-program-graph-v3/nevergone-runtime-correlation-20261020/function-effects.jsonl \
  --type-layout-hypotheses docs/evidence/semantic-program-graph-v3/nevergone-ccjoystick/type-layout-hypothesis.jsonl \
  --call-arguments docs/evidence/semantic-program-graph-v4/nevergone-runtime-call-arguments-20261020/call-arguments.jsonl \
  --call-argument-definitions docs/evidence/semantic-program-graph-v4/nevergone-runtime-call-arguments-20261020/argument-definitions.jsonl \
  --output docs/evidence/semantic-program-graph-v4/nevergone-runtime-call-arguments-20261020/semantic-program-graph.jsonl
```

Query the observations while keeping the exact call-site provenance:

```sh
PYTHONPATH=src python -m revenginstr.semantic_program_query \
  docs/evidence/semantic-program-graph-v4/nevergone-runtime-call-arguments-20261020/semantic-program-graph.jsonl \
  --view accepted-high-confidence \
  --kind operation \
  --function-entry 002d2f1c \
  --relation calls \
  --output /tmp/nevergone-calls-with-arguments.jsonl
```

The frozen graph has 90 nodes and 128 edges. It attaches observations to 36
exact resolved call sites, preserving 70 ordered argument tokens; 10 tokens
are constants. The exact-definition pass matches all 56 `def:` tokens to one
output row in the same caller's source P-code artifact; the other 14 tokens
remain non-definition tokens. The graph now attaches each resolution state
and definition row reference to its exact argument, pinned to the definition
analysis artifact. Rebuilding all outputs is deterministic, and the graph
validates against `SemanticProgramGraph/4`. The pinned replay
manifest records byte lengths and SHA-256 values for all source, output, and
schema artifacts.

The operand-trace pass emits 70 rows: 28 operand closures end without unresolved
references, 28 reach explicit memory/call boundaries, and 14 are non-definition
tokens. Across the traces it retains 87 producer rows, 33 exact operand links,
and 34 boundary rows. `LOAD`, `CALL`, `CALLIND`, and `INDIRECT` boundaries
prevent claims about memory contents or callee return values.

This records P-code operands at statically resolved calls. The definition
sidecar alone links each `def:` token to one exact producer row; the separate
operand trace expands syntactic input references within the stated limits and
stops at memory and call-result boundaries. Neither artifact evaluates runtime
values, infers resource names or prototypes, or claims complete call-site
coverage. The observations cover only two functions, and the existing runtime
capture corroborates function entries.
