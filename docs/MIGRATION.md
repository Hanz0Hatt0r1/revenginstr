# Migration from game repositories

`revenginstr` is the generic core for reverse-engineering analysis developed first in Nevergone and then exercised cross-project on NFS Shift.

## Move here

Project-neutral mechanisms belong here:

- portable Ghidra high-P-code export;
- corpus/schema/leakage validation;
- family/similarity and OOD primitives;
- monotone selective-routing helpers;
- generic receiver/type/vtable abstractions;
- callgraph/data-flow feature extraction;
- nested/grouped evaluation utilities;
- frozen validation mechanics.

## Keep in consumer repositories

Nevergone keeps Cocos-specific seed labels, class/vtable maps, game-specific training data and its frozen validation corpus.

NFS Shift keeps PC-retail addresses, P1/P2/P3 evidence, `HDVehicle` offsets, manager identities, resource/scene evidence and Shift-specific weak labels.

## Compatibility policy

Migration is incremental. A consumer may keep a thin wrapper with the historical command/file name while the implementation is delegated to `revenginstr`. Do not delete a working game-repository entrypoint until its generic replacement has been tested on the same retained evidence.

Stable generic format names use component versions rather than project/model experiment numbers, for example:

```text
REVENGINSTR.PcodeCorpus/1
REVENGINSTR.PcodeAudit/1
REVENGINSTR.ForeignGuard/1
REVENGINSTR.CallGraphMetrics/1
REVENGINSTR.Evidence/1
REVENGINSTR.ReceiverInference/1
```

JSON Schemas for `PcodeCorpus/1`, `CallGraphMetrics/1`, receiver type/inference
records, and `Evidence/1` live in `schemas/`; source identifiers are join metadata,
while evidence feature values remain numeric or boolean and project-neutral.
The generic one-function High P-code exporter preserves its existing metadata TSV
in `REVENGINSTR.GhidraFunctionPcodeFlow/1`; see
`docs/GHIDRA_FUNCTION_PCODE_FLOW.md` for the schema and read-only runner.

Nevergone experiment names such as v5.4/v9/v10 remain historical evaluation/model lineage, not public toolkit API versions.

## Current extraction state

`main` contains the portable P-code exporter and leakage audit, foreign-project
guard, callgraph/evidence aggregation, receiver planning and inference, function
family mining, selective classifiers and monotone accept-error routing. The
generic mechanisms are covered by one project-neutral test suite and CI.

The shared Ghidra scripts now also include a read-only ARM32 Itanium vtable-slot
exporter. It owns the symbol scan, pointer normalization and bounded contiguous
slot walk; consumer repositories still own the exported symbols/addresses and
interpretation catalogs.

The NFS Shift probe uses the shared exporter, audit and foreign guard when a
sibling `revenginstr` checkout is available, while retaining its historical
fallback. Nevergone's evidence pipeline similarly calls shared receiver,
callgraph and aggregation tools when available; its adapters preserve the
historical Nevergone record formats. Keep those fallbacks until each same-input
parity check passes in the consumer repository.

The next migrations should move one remaining duplicated implementation at a
time, with consumer-owned labels, thresholds, binaries, addresses, catalogs and
frozen validation data staying in their original repositories.
