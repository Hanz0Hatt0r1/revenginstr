# `CCJoyStick` secondary vtable-pointer review

Program identity is Nevergone `libcocos2dcpp.so`, SHA-256
`94b1ef6a9469e261183ac08199c5b0eb65c0c40b81918ca097bd32920828eb5e`.
The Ghidra P-code export is pinned by SHA-256
`0e75c17c7d13d05fc627be93a4e1dd78aef8ff7e49d9f207ee17f3deef05dda2`; the
memory-store export is pinned by SHA-256
`58393c3945018a6c026f3bef4ad5e2968b2201bd000f46ee9358f8b51efe1808`.

## Secondary address points

The ELF symbol table identifies `_ZTV10CCJoyStick` at `0x008e4220` with size
`0x230` bytes. The constructor at ELF address `0x00295ea0` and destructor at
`0x00295e08` both write three address points from this vtable group into
parameter-rooted fields. Ghidra's imported program maps these code and data
addresses by `+0x1000`.

| Receiver field | Vtable-relative address point | ELF address point | Ghidra address point |
| --- | ---: | ---: | ---: |
| `this+0xe0` | `0x1ec` | `0x008e440c` | `0x008f440c` |
| `this+0xe4` | `0x21c` | `0x008e443c` | `0x008f443c` |
| `this+0xe8` | `0x228` | `0x008e4448` | `0x008f4448` |

Each address lies inside the `_ZTV10CCJoyStick` range
`[0x008e4220, 0x008e4450)`. The constructor's PIC reference resolves through
GOT slot `0x0092edfc`: its `R_ARM_RELATIVE` relocation uses the word at file
offset `0x0092ddfc`, whose value is `0x008e4220`, the start of `_ZTV10CCJoyStick`.
Adding `0x1ec`, `0x21c`, or `0x228` therefore selects an address point within
that same vtable group.

The read-only Ghidra exports independently show 4-byte stores rooted at
parameter 0 for all three offsets in both functions:

| Field | Destructor store | Constructor store | Value addend in both functions |
| --- | --- | --- | ---: |
| `+0xe0` | `002a5e1c:30` | `002a5ebc:42` | `0x1ec` |
| `+0xe4` | `002a5e28:48` | `002a5ec8:60` | `0x21c` |
| `+0xe8` | `002a5e2c:50` | `002a5ecc:62` | `0x228` |

The store records are in `memory-store-access.jsonl`; the corresponding
address calculations and stores are in `pcode-flow.tsv`. The paired native
constructor/destructor writes, in-range ELF address points, symbol relocation,
and 4-byte field widths support `data_pointer` candidates. They do not identify
the pointed-to subobject type or member names, and they do not establish a
runtime observation or accepted layout.
