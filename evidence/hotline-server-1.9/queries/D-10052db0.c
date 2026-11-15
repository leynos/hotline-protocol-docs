
undefined4 * FUN_10052db0(uint param_1,uint param_2)

{
  undefined4 *puVar1;
  int iVar2;
  undefined1 auStack_20 [24];
  
  if ((param_1 & 0x80000000) != 0) {
    FUN_10027c30(3,0x65);
  }
  iVar2 = param_1 + 4;
  if ((param_2 & 1) == 0) {
    puVar1 = (undefined4 *).glue::NewHandleClear(iVar2);
    if (puVar1 == (undefined4 *)0x0) {
      FUN_10027c30(3,0x65);
    }
  }
  else {
    puVar1 = (undefined4 *).glue::TempNewHandle(iVar2,auStack_20);
    if (puVar1 == (undefined4 *)0x0) {
      FUN_10027c30(3,0x65);
    }
    .glue::HLock(puVar1);
    FUN_1006cc90(*puVar1,iVar2,0);
    .glue::HUnlock(puVar1);
  }
  return puVar1;
}

