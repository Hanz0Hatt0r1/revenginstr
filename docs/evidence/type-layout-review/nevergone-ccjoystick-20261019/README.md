# Nevergone `CCJoyStick` layout review

This bundle joins the existing consumer-owned `CCJoyStick::init` field-access
evidence to a separate exact-size review. The Nevergone `libcocos2dcpp.so`
SHA-256 is
`94b1ef6a9469e261183ac08199c5b0eb65c0c40b81918ca097bd32920828eb5e`.
The retained inputs and generated hypothesis are pinned in
[`manifest.json`](manifest.json).

`readelf` identifies the exported `CCJoyStick::create(int, int, bool, bool,
bool, bool)` function. The retained Thumb disassembly shows the factory loading
`0x154` into `r0`, calling scalar `operator new(unsigned int)`, retaining the
returned pointer, and passing it to `CCJoyStick::CCJoyStick()` before calling
`CCJoyStick::init`. The reviewer records this as a 340-byte exact size. The
independent observed field extent is 337 bytes, so the size is consistent and
leaves three unobserved bytes.

The map retains opaque type ID `nevergone:opaque-object-002a6584`. A separate
review records three four-byte `data_pointer` candidates targeting
`cocos2d::CCSprite` at `+0x104`, `+0x108`, and `+0x10c`; its source commit and
evidence boundary are described in
[`field-type-evidence.md`](field-type-evidence.md). Vtable identity for the
containing object and ownership remain unresolved.
Raw memory-store and parameter-load rows stay in the
[consumer evidence directory](https://github.com/Hanz0Hatt0r1/nevergone-recomp/tree/main/docs/evidence/field-store-load-cfg-ccjoystick-init).

## Reproduction

The source excerpt is retained in [`allocation-sequence.txt`](allocation-sequence.txt).
It can be regenerated from the pinned binary with:

```sh
readelf -Ws libcocos2dcpp.so | c++filt | rg 'CCJoyStick::create'
llvm-objdump -d --triple=thumbv7-linux-gnueabihf \
  --start-address=0x00296670 --stop-address=0x002966c8 libcocos2dcpp.so
```

The generic builder replay uses the consumer-owned inputs and the two review
rows retained here:

```sh
revenginstr-type-layout-hypothesis \
  --memory-store-jsonl path/to/field-store-load-cfg-ccjoystick-init/memory-store-access.jsonl \
  --parameter-loads-tsv path/to/field-store-load-cfg-ccjoystick-init/parameter-loads.tsv \
  --member-map-jsonl member-map.jsonl \
  --size-review-jsonl size-review.jsonl \
  --field-type-review-jsonl field-type-review.jsonl \
  --program-id 'nevergone:libcocos2dcpp.so' \
  --program-sha256 94b1ef6a9469e261183ac08199c5b0eb65c0c40b81918ca097bd32920828eb5e \
  --language-id ARM:LE:32:v8 --pointer-width-bytes 4 \
  --addressable-unit-bytes 1 --endianness little \
  --output type-layout-hypothesis.jsonl
```

The retained hypothesis contains 13 field offsets, a 337-byte minimum
observed extent, the reviewer-evidenced 340-byte exact size, and three
reviewed pointer target candidates. The type ID remains opaque; other field
types and a full class-layout claim remain unresolved.
