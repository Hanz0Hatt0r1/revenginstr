# Pinned disassembly for `00663030`

The input is the pinned retail executable `SHIFT.exe`, SHA-256
`eca479aa2d8dbb88bc55709d91ae5c7159ae1b00fc9555d6701000c26de8aee1`.
The range was read with:

```sh
objdump -d -Mintel --start-address=0x00663030 --stop-address=0x00663040 SHIFT.exe
```

```text
00663030: 83 fa 03             cmp    edx,0x3
00663033: 75 06                jne    0x66303b
00663035: 8d 41 7c             lea    eax,[ecx+0x7c]
00663038: c2 04 00             ret    0x4
0066303b: 33 c0                xor    eax,eax
0066303d: c2 04 00             ret    0x4
```

This shows the static selector-3 result at `this + 0x7c`; it does not prove
that selector 3 is supplied at either enclosing callsite.
