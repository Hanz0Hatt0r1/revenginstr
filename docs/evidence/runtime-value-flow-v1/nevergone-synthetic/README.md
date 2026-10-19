# Synthetic value-flow replay

This fixture uses invented program identities, static node IDs, addresses and
HMAC-shaped token strings to exercise the `/1` contract. It is not a capture
from the Nevergone process and contains no raw runtime values.

Run the CLI from the repository root:

```sh
python -m revenginstr.runtime_value_flow \
  docs/evidence/runtime-value-flow-v1/nevergone-synthetic/manifest.json \
  docs/evidence/runtime-value-flow-v1/nevergone-synthetic/correlation-report.json \
  docs/evidence/runtime-value-flow-v1/nevergone-synthetic/value-observations.jsonl \
  --output /tmp/runtime-value-flow-replay.json
```

The single selected field-write/read pair is reported as `witnessed`. Its
claim scope is only that pair; this fixture says nothing about the installed
game's actual field flow.
