
void FUN_10019180(int param_1,undefined4 param_2,undefined4 param_3)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  int local_f0 [2];
  undefined1 local_e8;
  undefined1 auStack_e7 [63];
  undefined1 local_a8;
  undefined1 auStack_a7 [63];
  byte local_68;
  undefined1 auStack_67 [83];
  
  if (*(int *)(param_1 + 0x78) != 0) {
    local_a8 = FUN_10042f80(*(undefined4 *)(*(int *)(param_1 + 0x70) + 0x2c),auStack_a7,0x3f);
    FUN_100691c0(*(undefined4 *)(param_1 + 0x70),0,0);
    local_68 = FUN_10042f80(*(undefined4 *)(*(int *)(param_1 + 0x74) + 0x2c),auStack_67,0x3f);
    FUN_100691c0(*(undefined4 *)(param_1 + 0x74),0,0);
    uVar3 = *(uint *)(param_1 + 0x78);
    *(undefined4 *)(param_1 + 0x78) = 0;
    uVar1 = FUN_10082630(param_1);
    if ((uVar3 <= uVar1) && (iVar2 = FUN_1001b000(param_1,uVar3), iVar2 != 0)) {
      FUN_10009990(iVar2,&local_a8);
      FUN_100539c0(iVar2 + 0x31,&local_68,local_68 + 1);
      FUN_10069f70(param_1,uVar3);
    }
  }
  FUN_1007a890(param_1,param_2,param_3);
  local_f0[0] = 0;
  iVar2 = FUN_1001ab80(param_1,local_f0);
  *(int *)(param_1 + 0x78) = iVar2;
  if ((iVar2 != 0) && (local_f0[0] != 0)) {
    FUN_10009b60(local_f0[0],&local_e8);
    FUN_100691c0(*(undefined4 *)(param_1 + 0x70),auStack_e7,local_e8);
    FUN_100691c0(*(undefined4 *)(param_1 + 0x74),local_f0[0] + 0x32,
                 *(undefined1 *)(local_f0[0] + 0x31));
  }
  return;
}

