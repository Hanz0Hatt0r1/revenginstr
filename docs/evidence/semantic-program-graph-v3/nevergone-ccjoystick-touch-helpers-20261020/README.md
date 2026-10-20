# Nevergone `CCJoyStick` touch helper replay

This package extends the exploratory `CCJoyStick` field-layout candidate with
three methods reached from the touch callbacks: `containsTouchLocation`,
`onTouchBegan`, and `onTouchEnd`. It is pinned to the original ARM32 ELF
SHA-256 `94b1ef6a9469e261183ac08199c5b0eb65c0c40b81918ca097bd32920828eb5e`.

The Ghidra project was opened with `-readOnly -noanalysis`. The parameter-field
export supplies 20 root-parameter-zero reads and the memory-store export
supplies two byte writes. P-code acquisition completed for all three methods
(256 operations total). The standalone type-layout builder adds four new
observed offsets (`+0x11c`, `+0x120`, `+0x124`, `+0x128`) while retaining the
340-byte allocation size.

The analysis prototypes for these methods are incomplete: they omit the C++
receiver and mislabel the `r0` root as an explicit argument. The accompanying
[`receiver-abi-evidence.md`](receiver-abi-evidence.md) documents the machine
register flow and matching `_ZTV10CCJoyStick` callback slots that support a
manual receiver-root mapping. This mapping is consumer evidence for the pinned
ELF, not a generic automatic prototype correction. The main semantic graph and
gold are unchanged; the new data only extends the exploratory layout
candidate set.

Candidate types are intentionally conservative: `+0x118`, `+0x119`, and
`+0x11a` are booleans; `+0x11c`, `+0x120`, `+0x124`, and `+0x128` are 32-bit
floating-point values; `+0x12c` is a 32-bit integer. No member names or accepted
types are added. `+0x104` is observed as a pointer passed to
`CCNode::stopAllActions`, consistent with the existing `cocos2d::CCSprite *`
candidate. That use does not independently establish the exact dynamic target
type, so this replay adds no candidate at `+0x104`. `setHitAreaWithRect` assigns
a `CCRect` beginning at `+0x11c` and clears `+0x12c`; `containsTouchLocation`
reads the four rectangle components and applies the integer threshold. The
`init` path obtains the director window size, constructs a `CCRect`, and passes
it to `setHitAreaWithRect`. The flat layout keeps the component access offsets
and does not add an overlapping aggregate row. `init` also zeros the floats at
`+0x13c/+0x140` and sets the byte at `+0x150`; these remain unnamed candidates.
Its four `CALLIND` sites remain unresolved and are retained as barriers.

The replay manifest pins raw exports, the receiver review, source inputs, and
the derived layout. The corresponding regression test rebuilds the layout and
validates the source records and file hashes.
