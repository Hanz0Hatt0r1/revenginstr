# Synthetic runtime-probe evaluation

These files are synthetic contract fixtures, not Nevergone runtime captures.
They contain four selected bounded native probes: three completed results and
one incomplete attempt. The expected replay reports 75% completion, two
decisive results among three completed probes, 750 milli-units of total
uncertainty reduction, two unlocked decision IDs, and one disagreement among
two comparable static predictions.

Run from the repository root:

```sh
python -m revenginstr.runtime_probe_evaluation \
  docs/evidence/runtime-probe-evaluation-v1/nevergone-synthetic/evaluation-manifest.json \
  docs/evidence/runtime-probe-evaluation-v1/nevergone-synthetic/request-plan.json \
  docs/evidence/runtime-probe-evaluation-v1/nevergone-synthetic/outcomes.jsonl \
  --output /tmp/runtime-probe-evaluation.json
```
