
void FUN_100248a0(undefined4 param_1,undefined4 param_2,int param_3,int param_4,int *param_5,
                 undefined4 param_6)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int local_420 [11];
  int local_3f4;
  int local_3ec;
  
  while ((param_4 != 0 && (*param_5 != 0))) {
    *param_5 = *param_5 + -1;
    iVar2 = FUN_1002c3b0(param_2,param_3 * (param_4 + -1) + 0x200,local_420,0xe4,0);
    if (iVar2 != 0xe4) {
      FUN_10027c30(1,9);
    }
    FUN_10025a60(param_1,local_420,param_4,param_6);
    iVar2 = local_3ec;
    param_4 = local_3f4;
    iVar4 = 0x20;
    while (((bVar1 = iVar4 != 0, iVar4 = iVar4 + -1, bVar1 && (local_420[0] != 0)) &&
           (iVar3 = FUN_1002c3b0(param_2,param_3 * (local_420[0] + -1) + 0x200,local_420,param_3,0),
           iVar3 != 0))) {
      FUN_10025c60(param_1,local_420);
    }
    if (iVar2 != 0) {
      FUN_100248a0(param_1,param_2,param_3,iVar2,param_5,param_6);
    }
  }
  return;
}

