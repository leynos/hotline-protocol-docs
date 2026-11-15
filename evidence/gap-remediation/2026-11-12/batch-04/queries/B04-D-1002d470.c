
void FUN_1002d470(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  undefined1 auStack_f0 [128];
  undefined2 local_30;
  undefined2 local_2e [13];
  undefined1 *local_14;
  
  if (param_1 == 0) {
    FUN_10027c30(1,2);
  }
  if (*(short *)(param_1 + 0x50) != 0) {
    FUN_10027c30(1,3);
  }
  local_2e[0] = 0;
  local_30 = 0;
  iVar1 = FUN_10052b70(0x200);
  local_14 = auStack_f0 + 0x80;
  uVar2 = FUN_1002d130(param_1,iVar1 + 0x58,iVar1 + 0x34,iVar1 + 0x44);
  *(undefined4 *)(iVar1 + 0x54) = uVar2;
  *(undefined4 *)(iVar1 + 0x48) = 0x494e464f;
  *(undefined4 *)(iVar1 + 0x28) = 0x44415441;
  *(undefined4 *)(iVar1 + 0x38) = 0x4d414352;
  *(undefined4 *)(iVar1 + 0x10) = 0x46494c50;
  *(undefined2 *)(iVar1 + 0x14) = 1;
  *(undefined2 *)(iVar1 + 0x26) = 3;
  uVar2 = FUN_1007fc50(param_1,0x21,&local_30);
  if ((short)uVar2 != 0) {
    local_30 = 0;
    FUN_10028190(uVar2,0,0);
  }
  uVar2 = FUN_1007fe70(param_1,0x21,local_2e);
  if ((short)uVar2 != 0) {
    local_2e[0] = 0;
    FUN_10028190(uVar2,0,0);
  }
  *(undefined2 *)(param_1 + 0x50) = local_30;
  *(undefined2 *)(param_1 + 0x52) = local_2e[0];
  *(int *)(param_1 + 0x48) = iVar1;
  return;
}

