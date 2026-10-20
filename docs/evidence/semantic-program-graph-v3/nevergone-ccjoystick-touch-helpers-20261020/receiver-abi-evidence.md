# Nevergone `CCJoyStick` touch helper receiver review

This consumer-specific extension records three methods reached from the
`CCJoyStick` touch callbacks. The source is the original shipped ARM32 ELF
`/home/pes/ghidra_projects/nevergone/armeabi-v7a/libcocos2dcpp.so`, SHA-256
`94b1ef6a9469e261183ac08199c5b0eb65c0c40b81918ca097bd32920828eb5e`, analyzed
read-only in the existing Ghidra 12.1.2 project. No Ghidra database was changed.

## Why parameter 0 is reviewed as the receiver

Ghidra's analysis prototypes for `containsTouchLocation` (`CCTouch *`),
`onTouchBegan` (`CCPoint`), and `onTouchEnd` (`CCPoint`) omit the implicit C++
receiver and report `__stdcall`. They are not used as receiver truth here.
The filtered vtable export in `vtable-touch-slots.tsv` places
`ccTouchBegan` at primary address-point slot `+0x178` and `ccTouchEnded` at
slot `+0x180` of `_ZTV10CCJoyStick`. The machine instructions show incoming
`r0` preserved through their callback-to-helper calls:

- `CCJoyStick::ccTouchBegan` at `0x002a6300` executes `mov r7,r0` at
  `0x002a6304`, calls `containsTouchLocation` with that value at `0x002a6308`,
  then passes the same `r7` in `r0` to `onTouchBegan` at `0x002a6362`.
- `CCJoyStick::ccTouchEnded` at `0x002a63ec` executes `mov r6,r0` at
  `0x002a63ee` and passes it in `r0` to `onTouchEnd` at `0x002a642c`.
- `containsTouchLocation` at `0x002a60c8` executes `mov r4,r0` at
  `0x002a60ce`, reads fields relative to `r4`, and calls a function from
  `[r4] + 0xcc` with `r0 = r4`.
- `onTouchBegan` at `0x002a6284` executes `mov r4,r0` at `0x002a6286` and
  reads/writes member offsets relative to `r4`; it also calls virtual methods
  with `r0 = r4`.
- `onTouchEnd` at `0x002a63a8` executes `mov r4,r0` at `0x002a63aa` and
  reads/writes member offsets relative to that value.

The parameter-field exporter maps each direct access to root parameter index 0.
The accompanying member-map rows are therefore explicit human-reviewed receiver
roots, not signatures inferred from Ghidra's incomplete prototypes. The review
is valid only for this pinned program and these functions.

## Hit-area semantics

`CCJoyStick::setHitAreaWithRect` at `0x002a6570` supplies an independent
owner-method cross-check. Ghidra's prototype marks parameter 0 as
`CCJoyStick * this` and parameter 1 as `CCRect`; the instruction at
`0x002a6574` computes `this + 0x11c`, and the call at `0x002a6578` resolves to
`cocos2d::CCRect::operator=`. The same method stores zero at `this + 0x12c`
(`0x002a657e`). The four float loads from `+0x11c`, `+0x120`, `+0x124`, and
`+0x128` in `containsTouchLocation` therefore observe components of the
region assigned as a `CCRect`. The flat layout replay keeps those component
access starts; it does not add a second, overlapping aggregate field row.

`containsTouchLocation` treats `+0x12c` as a non-negative integer threshold,
converts it to float, and compares it with a point distance. A positive value
can satisfy the test before the rectangle component checks; the setter resets
it to zero. This supports an integer candidate, but the field remains unnamed
and unaccepted.

## Observed field evidence and conservative type candidates

- `+0x104`: a four-byte load is passed to `CCNode::stopAllActions`, confirming pointer use. This is consistent with the existing `cocos2d::CCSprite *` candidate, but it does not establish the exact dynamic target type, so this package adds no new type candidate there.
- `+0x118`, `+0x119`, `+0x11a`: one-byte values control conditional branches;
  boolean candidates.
- `+0x11c`, `+0x120`, `+0x124`, `+0x128`: `vldr.32` values participate in
  floating-point comparisons and additions; 32-bit floating-point candidates.
- `+0x12c`: loaded as an integer, checked against zero, then converted from
  signed integer to float for the distance comparison; 32-bit integer candidate.

The review adds no field names and accepts no field types. It does not infer
runtime behavior. The object allocation remains 340 bytes. The existing
semantic graph and its gold are unchanged; these rows extend only the
exploratory layout candidate set because the current Ghidra prototype exporter
has not recovered these implicit receivers.

## Reproduce exports

The vtable, prototype, parameter-field, and P-code exports are the files in
this folder. They were produced with the repository's read-only Ghidra runners
against the pinned project and Java 21. The selected vtable rows came from the
complete exporter output with compressed SHA-256
`8d348b4e0372fd325d17f7c3f19c8f64b5b98f6b93f4ab611f5122fb3899dccd`.
P-code acquisition is complete for all three methods. `README.md` and
`replay-manifest.json` pin every retained export and the base artifacts used
to derive the layout extension.
