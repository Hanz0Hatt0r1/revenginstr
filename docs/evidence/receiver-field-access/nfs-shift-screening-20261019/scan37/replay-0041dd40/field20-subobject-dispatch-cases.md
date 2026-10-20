# Returned subobject dispatch cases

This excerpt records the two getter bodies used to classify the returned
subobjects. The source is the retained Ghidra decompiler export
`/home/pes/ghidra_projects/shift/SHIFT.exe.c`, SHA-256
`512753a5f91898885263c91664a3d3fa3e07bfd58b72d3a5f89c402a00760ee9`.
Original export line numbers are shown in the comments.

```c
/* SHIFT.exe.c:570541-570551 */
int __fastcall FUN_00676040(int param_1,int param_2,uint param_3)
{
  if (param_2 == 1) {
    return param_1 + 0x74;
  }
  if ((param_2 == 4) && (param_3 < 3)) {
    return param_3 * 0x5c + 0x128 + param_1;
  }
  return 0;
}

/* SHIFT.exe.c:571308-571328 */
int __fastcall FUN_006770b0(int param_1,undefined4 param_2,uint param_3)
{
  switch(param_2) {
  case 1:
    return param_1 + 0x74;
  case 2:
    if (param_3 < 2) {
      return param_1 + 0x4c0 + param_3 * 0x48;
    }
    break;
  case 4:
    if (param_3 < 10) {
      return param_3 * 0x5c + 0x128 + param_1;
    }
    break;
  case 5:
    return param_1 + 0x550;
  }
  return 0;
}
```

The selectors above are static cases. The enclosing `CALLIND` flow does not
bind the runtime selector register, so these cases do not identify which
receiver was returned in a particular execution.
