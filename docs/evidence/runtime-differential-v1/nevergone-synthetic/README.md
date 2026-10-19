# Synthetic runtime differential replay

This replay compares the existing synthetic Nevergone baseline correlation with a synthetic treatment containing one extra `MEPlayer::filpPlayer` function-entry observation. The declared intervention is a horizontal-control action; all capture data and the intervention are synthetic. The changed signature is ranked as `correlation` evidence only.

Reproduce the treatment correlation from the repository root:

```sh
PYTHONPATH=src python -m revenginstr.runtime_static_correlation \
  docs/evidence/semantic-program-graph-v3/nevergone-ccjoystick/semantic-program-graph.jsonl \
  docs/evidence/runtime-static-correlation-v1/nevergone-synthetic/static-identity.json \
  docs/evidence/runtime-differential-v1/nevergone-synthetic/treatment-capture.json \
  docs/evidence/runtime-differential-v1/nevergone-synthetic/treatment-observations.jsonl \
  --output /tmp/nevergone-treatment-correlation.json
```

Run the pairwise comparison using the regenerated treatment report and the pinned baseline report:

```sh
PYTHONPATH=src python -m revenginstr.runtime_differential \
  docs/evidence/runtime-static-correlation-v1/nevergone-synthetic/correlation.json \
  /tmp/nevergone-treatment-correlation.json \
  docs/evidence/runtime-differential-v1/nevergone-synthetic/intervention.json \
  --output /tmp/nevergone-differential.json
```
