# Nevergone `CCJoyStick` field-type review

The pinned binary is Nevergone 1.0.9 ARMv7 `libcocos2dcpp.so`, SHA-256
`94b1ef6a9469e261183ac08199c5b0eb65c0c40b81918ca097bd32920828eb5e`.

The consumer-side static review identifies `CCJoyStick::init` storing three
empty `cocos2d::CCSprite` containers at `this + 0x104`, `this + 0x108`, and
`this + 0x10c`. For `+0x104`, the separate v13 proof follows the direct factory
call through constructor-proven `cocos2d::CCSprite` return evidence. The pinned
Ghidra STORE observations report four-byte writes at each of those offsets.
The raw Ghidra field capture uses function entry `0x2a6584`; the exported ELF
Thumb symbol is `0x296585` (code address `0x296584`). Both captures identify the
same binary hash.

## Sprite pointers

The review adds only `data_pointer`, width 4, and target candidate
`cocos2d::CCSprite` for the three observed fields. The containing object stays
opaque, and this does not infer other fields, ownership, inheritance, vtable,
or full class layout. Source review records are pinned to Nevergone consumer
commit `30d2820a3f8e02295656d68562fc2b8b81104a5f` in
[`field-type-review.jsonl`](field-type-review.jsonl).

## Scalar parameter copies

The exact initializer symbol is
`CCJoyStick::init(int, int, bool, bool, bool, bool)`. The consumer
`GhidraParameterStoreField/1` capture records direct formal-parameter copies
into the joystick at these offsets: parameter 2 to `+0x110` (4 bytes),
parameter 1 to `+0x114` (4 bytes), and parameters 3, 4, 5, and 6 to
`+0x118`, `+0x119`, `+0x11a`, and `+0x139` (1 byte each). Counting `this` as
parameter 0, the signature makes parameters 1 and 2 integers and parameters
3 through 6 booleans. The review records those as type candidates without
assigning member names or interpreting their runtime meaning.

The source `parameter-stores.tsv` has SHA-256
`308a90c88b719f1bb0bdbd3f605dd18968a2fe4e284b51cde6ac2a4c63749bc0`; the
corresponding `memory-store-access.jsonl` has SHA-256
`391c0444194daa95b554670f8c29a112ca17625549290129c521c13f52311eda`. The
function signature and three sprite containers are recorded in the
[joystick dock evidence](https://github.com/Hanz0Hatt0r1/nevergone-recomp/blob/30d2820a3f8e02295656d68562fc2b8b81104a5f/docs/evidence/player-joystick-dock.md),
SHA-256 `cbb7e9caca7e112a4b151a761cc03dadb2021e10e73f41e516406ebc82e316cf`.
The exact `+0x104` factory return proof is recorded in the
[v13 field-recovery evidence](https://github.com/Hanz0Hatt0r1/nevergone-recomp/blob/30d2820a3f8e02295656d68562fc2b8b81104a5f/docs/evidence/ccjoystick-field-recovery-v13.md),
SHA-256 `029ba4f9ec66520e2de59dad6b6641ea1114d75c85c922fb951e89fccc60c717`.
