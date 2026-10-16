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
```

Nevergone experiment names such as v5.4/v9/v10 remain historical evaluation/model lineage, not public toolkit API versions.

## First extraction milestone

The first milestone extracts the ARM32/x86-32 portable P-code contract and the foreign-project OOD guard that were validated by the first 1000-function `SHIFT.exe` transfer probe. The next extraction milestone is callgraph/evidence primitives followed by receiver/type/vtable inference.
