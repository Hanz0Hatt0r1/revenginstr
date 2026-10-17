# Semantic role labels and evaluation

The shared taxonomy uses bounded, multi-label roles: lifecycle/init/shutdown,
accessor/getter/setter, constructor/destructor/factory, parser/decoder/loader,
serializer/save writer, state update/tick, input handler, render submission,
animation/action update, physics/collision query, combat/state transition,
resource lookup/cache, callback/scheduler adapter, network/media/runtime
adapter, utility/container/math, `unknown`, and `compound`.

Consumers keep the actual annotation and prediction rows in their own
repositories. [`SemanticRoleLabel/1`](../schemas/semantic-role-label-v1.schema.json)
accepts adjudicated rows only. [`SemanticRolePrediction/1`](../schemas/semantic-role-prediction-v1.schema.json)
records one model's discrete multi-label output. Both carry opaque function and
family ids plus caller-owned dataset/split ids; neither schema includes
addresses or project-specific fields.

Evaluate a paired split:

```sh
revenginstr-semantic-role-evaluate labels.jsonl predictions.jsonl \
  --training-families train-families.jsonl \
  --output role-evaluation.json
```

The evaluator requires exact one-to-one function ids, matching family ids,
matching dataset/split ids, one model id, and adjudicated labels. When given a
training-only `FunctionFamilies/1` artifact, it verifies that no evaluation
function id or family appears in training and fails if any overlap exists. Without that
artifact, the report says `not_checked`; the tool does not claim that the split
is held out.

The [`SemanticRoleEvaluation/1`](../schemas/semantic-role-evaluation-v1.schema.json)
report records the exact input hashes and aggregate per-role precision/recall/F1,
micro-F1, macro-F1 over roles appearing in truth or predictions, and exact
multi-label match accuracy. It omits function ids, family ids, and row-level
predictions. The macro metric's observed-role definition avoids treating
unrepresented taxonomy entries as measured negatives.

The `semantic-role-evaluate` stage is available to pinned benchmark manifests.
These metrics evaluate discrete labels; they do not measure calibration,
evidence quality, or factual support for a role. Structured summaries must
continue linking every claim to Effect IR evidence.
