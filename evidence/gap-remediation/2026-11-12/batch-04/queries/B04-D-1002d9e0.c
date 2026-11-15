
void FUN_1002d9e0(int param_1)

{
  undefined4 uVar1;
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
  uVar1 = FUN_10052b70(0x294);
  local_14 = auStack_f0 + 0x80;
  uVar2 = FUN_1007fc50(param_1,0x32,&local_30);
  if ((short)uVar2 != 0) {
    local_30 = 0;
    FUN_10028190(uVar2,0,0);
  }
  uVar2 = FUN_1007fe70(param_1,0x32,local_2e);
  if ((short)uVar2 != 0) {
    local_2e[0] = 0;
    FUN_10028190(uVar2,0,0);
  }
  *(undefined2 *)(param_1 + 0x50) = local_30;
  *(undefined2 *)(param_1 + 0x52) = local_2e[0];
  *(undefined4 *)(param_1 + 0x4c) = uVar1;
  return;
}

