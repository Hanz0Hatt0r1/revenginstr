# Synthetic runtime address correlation replay

This replay uses the real Nevergone `CCJoyStick` SemanticProgramGraph/3 and
its pinned executable SHA-256. The runtime addresses, load bias, six events,
and dropped-event gap are synthetic. They verify address normalization and
report behavior; they are not observations from the game or a phone capture.

Reproduce the pinned output directly:

```sh
PYTHONPATH=src python -m revenginstr.runtime_static_correlation \
  docs/evidence/semantic-program-graph-v3/nevergone-ccjoystick/semantic-program-graph.jsonl \
  docs/evidence/runtime-static-correlation-v1/nevergone-synthetic/static-identity.json \
  docs/evidence/runtime-static-correlation-v1/nevergone-synthetic/capture-manifest.json \
  docs/evidence/runtime-static-correlation-v1/nevergone-synthetic/observations.jsonl \
  --output /tmp/runtime-static-correlation.json
```

Run the same inputs through the benchmark orchestrator:

```sh
PYTHONPATH=src python -m revenginstr.benchmark \
  docs/evidence/runtime-static-correlation-v1/nevergone-synthetic/benchmark-manifest.json \
  --mode smoke --output /tmp/runtime-static-correlation-benchmark.json
```

The manifest pins every input and schema. Remove `correlation.generated.json`
before rerunning because benchmark outputs must not exist at run start.
