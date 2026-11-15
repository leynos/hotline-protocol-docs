
undefined4 FUN_1002db60(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined1 auStack_100 [128];
  short local_40;
  short local_3e;
  undefined4 local_3c;
  undefined4 *local_38;
  undefined4 local_34;
  undefined1 *local_1c;
  
  if (param_1 == 0) {
    FUN_10027c30(1,2);
  }
  if (*(short *)(param_1 + 0x50) != 0) {
    FUN_10027c30(1,3);
  }
  local_3e = 0;
  local_40 = 0;
  iVar1 = FUN_10052b70(0x294);
  local_1c = auStack_100 + 0x80;
  uVar2 = FUN_1007fc50(param_1,0x32,&local_40);
  if ((short)uVar2 != 0) {
    local_40 = 0;
    FUN_10028190(uVar2,0,0);
  }
  uVar2 = FUN_1007fe70(param_1,0x32,&local_3e);
  if ((short)uVar2 != 0) {
    local_3e = 0;
    FUN_10028190(uVar2,0,0);
  }
  uVar2 = FUN_10052db0(0x4a,0);
  local_34 = uVar2;
  local_38 = (undefined4 *)FUN_10053290();
  *local_38 = 0x52464c54;
  *(undefined2 *)(local_38 + 1) = 1;
  *(undefined2 *)(local_38 + 10) = 2;
  uVar3 = .glue::GetEOF((int)local_40,&local_3c);
  if ((short)uVar3 != 0) {
    FUN_10028190(uVar3,0,0);
  }
  *(undefined4 *)((int)local_38 + 0x2a) = 0x44415441;
  *(undefined4 *)((int)local_38 + 0x2e) = local_3c;
  *(undefined4 *)(iVar1 + 8) = local_3c;
  uVar3 = .glue::GetEOF((int)local_3e,&local_3c);
  if ((short)uVar3 != 0) {
    FUN_10028190(uVar3,0,0);
  }
  *(undefined4 *)((int)local_38 + 0x3a) = 0x4d414352;
  *(undefined4 *)((int)local_38 + 0x3e) = local_3c;
  *(undefined4 *)(iVar1 + 0xc) = local_3c;
  FUN_10053310(local_34);
  *(short *)(param_1 + 0x50) = local_40;
  *(short *)(param_1 + 0x52) = local_3e;
  *(int *)(param_1 + 0x4c) = iVar1;
  return uVar2;
}

