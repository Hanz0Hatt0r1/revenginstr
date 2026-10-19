# Cross-architecture return-shape regression

This small benchmark combines two real Ghidra 12.1.2 captures and their
source-backed gold:

- the 32-bit x86 direct-call possible-tail-return fixture;
- the 64-bit x86 statically resolved indirect-call fixture.

`hypotheses.jsonl` and `gold.jsonl` aggregate the function rows from those
captures. `evaluation.json` scores three gold functions and five candidates.
Return-shape coverage is 3/5, accuracy among known predictions is 100%, and no
candidate reaches the 0.95 acceptance threshold. This is a focused
cross-architecture regression set, not a consumer corpus or calibration set.
The original captures and C source evidence remain in their respective fixture
directories.

Recreate the combined evaluation from the repository root with:

```sh
revenginstr-function-prototype-evaluate \
  tests/fixtures/prototype-return-shape-benchmark/hypotheses.jsonl \
  tests/fixtures/prototype-return-shape-benchmark/gold.jsonl \
  --format-version 2 --output /tmp/return-shape-evaluation.json
```

The checked-in aggregate files also normalize both gold sources to one dataset
and split id; that label normalization is handled by the regression test.
