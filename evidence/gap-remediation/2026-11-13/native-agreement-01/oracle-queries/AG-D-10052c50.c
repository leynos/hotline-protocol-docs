
undefined4 * FUN_10052c50(uint param_1,uint param_2)

{
  undefined4 *puVar1;
  undefined1 auStack_20 [24];
  
  if ((param_1 & 0x80000000) != 0) {
    FUN_10027c30(3,0x65);
  }
  if ((param_2 & 1) == 0) {
    puVar1 = (undefined4 *).glue::NewHandle(param_1 + 4);
  }
  else {
    puVar1 = (undefined4 *).glue::TempNewHandle(param_1 + 4,auStack_20);
  }
  if (puVar1 == (undefined4 *)0x0) {
    FUN_10027c30(3,0x65);
  }
  *(undefined4 *)*puVar1 = 0;
  return puVar1;
}

