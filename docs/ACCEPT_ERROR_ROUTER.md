# Accept-error router

`REVENGINSTR.AcceptErrorRouter/1` is a project-neutral second-stage production router for already-selective classifiers.

It preserves the semantic class prediction and all non-accept actions. Only a base `accept` can be downgraded to `escalate`.

```text
base prediction/action
       |
       +-- review/escalate -> preserve
       |
       +-- accept
             |
             v
       correctness meta-model
             |
             +-- score >= threshold -> accept
             +-- score <  threshold -> escalate
```

Promotions are structurally impossible.

## Training input

The router consumes family-held-out OOF JSONL from a base classifier. Each row must provide:

```text
id
family_id
truth
prediction
action
probabilities
```

The standard revenginstr selective classifiers additionally provide family similarity, competing similarity and contrast margin; these are used when present.

Optional `REVENGINSTR.Evidence/1` supplies sanitized numeric features.

## Meta features

The generic matrix contains:

- aligned class probabilities;
- top-two probability gap;
- probability entropy;
- maximum probability;
- predicted-family similarity;
- competing-family similarity;
- contrast margin;
- predicted-class one-hot;
- sanitized numeric evidence.

Evidence keys containing raw identity terms such as source/function names, addresses, class-name/vtable identities or labels are excluded defensively.

## Leakage-safe production calibration

Only base `accept` rows train the correctness model. Cross-fitted scores are produced with `StratifiedGroupKFold` using `family_id` as the grouping boundary and correctness as the stratification target.

A single production threshold is selected under two constraints:

```text
kept accept precision >= target precision
kept accept coverage >= base accept coverage - max coverage loss
```

The final global/per-predicted-class meta models are then trained on every base OOF accept after the threshold is frozen.

This packaging step is not a new unbiased semantic evaluation. Consumers should retain their nested/cross-fitted experiment result as the primary evaluation and treat the packaged router as deployment calibration.

## Train

```bash
revenginstr-accept-router-train \
  model/oof_predictions.jsonl \
  accept-router \
  --evidence evidence.jsonl \
  --target-accept-precision 0.97 \
  --max-accept-coverage-loss 0.04
```

Outputs:

```text
accept-router/accept_error_router.joblib
accept-router/manifest.json
accept-router/crossfit_accept_scores.jsonl
```

## Inference

First run a revenginstr base classifier, then:

```bash
revenginstr-accept-router-infer \
  accept-router \
  predictions.jsonl \
  --evidence evidence.jsonl \
  --output routed.jsonl
```

The output preserves base fields and adds:

```text
accept_error_router_format
base_action
accept_correctness_probability
accept_router_changed
accept_error_router_reason
accept_error_router_evidence_feature_count
```

`action` is the routed action.
The reason identifies the policy branch: preserve a non-accept action, keep an
accept at or above threshold, or downgrade an accept below threshold. The
evidence count reports how many configured numeric evidence features were
present for a scored accept. It does not attribute the score to an individual
feature. The two added fields are optional in the `/1` row schema so older
router outputs remain valid.

## Frozen labeled gate

The crossfit precision and coverage in the router manifest are calibration
statistics. They are not an independent gate because the threshold is selected
from those crossfit outcomes. Evaluate a separate labeled population after
freezing the router:

```bash
revenginstr-accept-router-gate \
  frozen-routed.jsonl accept-router/manifest.json model/oof_predictions.jsonl \
  --output frozen-router-gate.json --strict
```

The holdout input follows
[`FrozenAcceptRouterGate/1` rows](../schemas/frozen-accept-router-gate-row-v1.schema.json).
In addition to routed fields, each row must include `truth`, `family_id`, a
consumer-defined `critical_case`, an explicit `evidence_conflict_detected`
boolean, `population` (`in_distribution` or `ood`), and whether external
evidence was present. The evaluator requires the router manifest's exact OOF
hash and checks both identity and family disjointness against the training OOF.
It reports aggregate precision, coverage, critical false-accept rate, conflict
accepts, monotonicity checks, and coverage by predicted class, population and
evidence availability. Reports contain hashes and counts, never row identities.

The gate passes only when the precision, coverage and critical-error limits pass;
the critical subset is present; evidence conflicts are never accepted; all
routes obey the frozen policy; and the gate population is identity- and
family-disjoint from router calibration. Missing consumer annotations are an
error, not an implicit `false` value.

## Consumer boundary

Nevergone v9/v10 remain the historical evaluation/packaging lineage that established this mechanism. Their artifacts should not be renamed in place.

Other projects must recalibrate their own router from their own family-held-out labeled OOF. A Nevergone-trained accept router must not be used as semantic authority for NFS Shift or another title.
