# Nevergone mobile static analysis: `Decode` and level loading

This package records a manual ARM32/Thumb analysis run in Termux on the
connected Android phone. The target came from the installed original package
`com.hippiegame.nevergone` (version 1.0.9). Its
`lib/armeabi-v7a/libcocos2dcpp.so` SHA-256 is
`94b1ef6a9469e261183ac08199c5b0eb65c0c40b81918ca097bd32920828eb5e`, matching
the artifact already pinned in this repository.

The analyzer was `radare2 6.2.4` running natively on the phone. The captured
[`symbols.txt`](symbols.txt) and [`disassembly.txt`](disassembly.txt) are its
raw outputs; [`manifest.json`](manifest.json) pins their hashes and address
mapping. R2 reports ELF virtual addresses. The existing artifact identity uses
a Ghidra image base of `0x10000`, so a graph address equals the ELF VMA plus
`0x10000`.

## Recovered behavior

`cocos2d::Decode(unsigned char *src, int length, unsigned char *dst,
unsigned int key)` is a byte transform. The loop keeps a phase counter from 0
through 126, then resets it to zero. Each output byte is therefore:

```text
dst[i] = (((src[i] XOR key) - (i mod 127)) mod 256)
```

At `CCFileUtilsAndroid::getFileData`'s call site, the caller allocates a
same-length output buffer and sets `key` to `1` before calling `Decode`; it
then releases the original buffer. This establishes the transform for this
asset-loading path. It does not imply a general-purpose encryption scheme.

`GameLevels::LoadGameLevels` obtains file data through the Cocos file utility,
wraps it as `HPData`, then calls the scene, actions, global, and port-node
loaders in that order. A false result from the first three stages returns
false immediately; the port-node stage's result is returned directly.

## Limits

The phone run used symbol lookup and targeted disassembly, not Ghidra or an
automated decompiler. R2 noted that it did not apply ELF relocations; the
`Decode` loop and the caller's register setup are local instructions and do
not depend on resolved external relocations. This is a manual recovery
anchored to the pinned binary and the saved disassembly, not a generalized
decoder rule for other builds.
