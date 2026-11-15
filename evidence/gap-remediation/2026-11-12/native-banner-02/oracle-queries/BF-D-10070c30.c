
undefined4 * FUN_10070c30(int param_1)

{
  undefined4 *puVar1;
  undefined4 *puVar2;
  undefined1 auStack_20 [24];
  
  if (param_1 == 0) {
    FUN_10027c30(1,2);
  }
  puVar1 = (undefined4 *).glue::TempNewHandle(param_1 + 0x10,auStack_20);
  if (puVar1 == (undefined4 *)0x0) {
    FUN_10027c30(3,0x65);
  }
  .glue::HLockHi(puVar1);
  puVar2 = (undefined4 *)*puVar1;
  *puVar2 = 0;
  puVar2[1] = puVar1;
  puVar2[2] = 0;
  puVar2[3] = param_1;
  return puVar2 + 4;
}

