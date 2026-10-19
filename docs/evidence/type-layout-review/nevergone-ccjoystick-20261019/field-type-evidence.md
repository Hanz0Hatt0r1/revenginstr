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

The review adds only `data_pointer`, width 4, and target candidate
`cocos2d::CCSprite` for the three observed fields. The containing object stays
opaque, and this does not infer other fields, ownership, inheritance, vtable,
or full class layout. Source review records are pinned to Nevergone consumer
commit `30d2820a3f8e02295656d68562fc2b8b81104a5f` in
[`field-type-review.jsonl`](field-type-review.jsonl).
