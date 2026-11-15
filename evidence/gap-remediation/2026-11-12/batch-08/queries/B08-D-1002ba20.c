
void FUN_1002ba20(short *param_1)

{
  undefined4 uVar1;
  int local_cc;
  short local_a0 [2];
  undefined4 local_9c;
  undefined1 auStack_98 [64];
  undefined1 auStack_58 [2];
  undefined4 local_56;
  undefined1 auStack_52 [78];
  
  if (param_1 == (short *)0x0) {
    FUN_10027c30(1,2);
  }
  FUN_1002e120(param_1);
  uVar1 = .glue::FindFolder((int)*param_1,0x74727368,1,local_a0,&local_9c);
  if ((short)uVar1 != 0) {
    FUN_10028190(uVar1,0,0);
  }
  uVar1 = .glue::FSMakeFSSpec((int)local_a0[0],local_9c,0,auStack_58);
  if ((short)uVar1 != 0) {
    FUN_10028190(uVar1,0,0);
  }
  uVar1 = .glue::FSpCatMove(param_1,auStack_58);
  if ((short)uVar1 != 0) {
    if ((short)uVar1 == -0x30) {
      if (*(char *)(param_1 + 3) == '\0') {
        uVar1 = FUN_1007f230((int)*param_1,*(undefined4 *)(param_1 + 1),auStack_98);
        if ((short)uVar1 != 0) {
          FUN_10028190(uVar1,0,0);
        }
      }
      else {
        .glue::BlockMoveData(param_1 + 3,auStack_98,*(byte *)(param_1 + 3) + 1);
      }
      FUN_1002bf70(auStack_58,1,auStack_98,0);
      uVar1 = FUN_10080140(param_1,auStack_58,auStack_98);
      if ((short)uVar1 == -0x516) {
        local_9c = FUN_1002e1b0((int)*param_1,*(undefined4 *)(param_1 + 1),param_1 + 3,0);
        uVar1 = .glue::FSpRename(param_1,auStack_98);
        if ((short)uVar1 != 0) {
          FUN_10028190(uVar1,0,0);
        }
        uVar1 = .glue::CatMove((int)*param_1,local_9c,local_cc + 0x3535,local_56,auStack_52);
        if ((short)uVar1 != 0) {
          FUN_10028190(uVar1,0,0);
        }
      }
      else if ((short)uVar1 != 0) {
        FUN_10028190(uVar1,0,0);
      }
    }
    else {
      FUN_10028190(uVar1,0,0);
    }
  }
  return;
}

