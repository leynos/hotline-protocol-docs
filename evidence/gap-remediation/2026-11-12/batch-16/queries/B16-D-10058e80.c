
undefined4 * FUN_10058e80(int param_1,short param_2,short param_3)

{
  undefined4 *puVar1;
  
  puVar1 = *(undefined4 **)(param_1 + 0x10);
  if (-1 < *(char *)(param_1 + 0x4c)) {
    return (undefined4 *)0x0;
  }
  if (param_2 == 0) {
    if (param_3 == 1) {
      for (; puVar1 != (undefined4 *)0x0; puVar1 = (undefined4 *)*puVar1) {
        if (((*(short *)((int)puVar1 + 0x1a) == 3) && ((*(byte *)(puVar1 + 7) >> 6 & 1) == 0)) &&
           ((uint)puVar1[2] <= (uint)puVar1[3])) {
          return puVar1;
        }
      }
    }
    else {
      for (; puVar1 != (undefined4 *)0x0; puVar1 = (undefined4 *)*puVar1) {
        if ((*(short *)((int)puVar1 + 0x1a) == 3) && ((*(byte *)(puVar1 + 7) >> 6 & 1) == 0)) {
          return puVar1;
        }
      }
    }
  }
  else if (param_3 == 1) {
    for (; puVar1 != (undefined4 *)0x0; puVar1 = (undefined4 *)*puVar1) {
      if (((*(short *)((int)puVar1 + 0x1a) == 3) && (*(short *)(puVar1 + 6) == param_2)) &&
         (((*(byte *)(puVar1 + 7) >> 6 & 1) == 0 && ((uint)puVar1[2] <= (uint)puVar1[3])))) {
        return puVar1;
      }
    }
  }
  else {
    for (; puVar1 != (undefined4 *)0x0; puVar1 = (undefined4 *)*puVar1) {
      if (((*(short *)((int)puVar1 + 0x1a) == 3) && (*(short *)(puVar1 + 6) == param_2)) &&
         ((*(byte *)(puVar1 + 7) >> 6 & 1) == 0)) {
        return puVar1;
      }
    }
  }
  return (undefined4 *)0x0;
}

