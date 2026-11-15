
void FUN_10024400(undefined4 param_1,uint param_2,int *param_3,undefined4 param_4,uint param_5,
                 undefined4 param_6,undefined4 param_7)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint local_38;
  undefined4 local_34;
  
  iVar5 = param_3[1];
  iVar4 = *param_3;
  iVar2 = iVar4;
  if ((param_2 - 1 & iVar5 << 3) == 0) {
    uVar1 = iVar5 * 8;
    iVar2 = FUN_10023de0(param_1,param_2,param_7,uVar1 / param_2 + 1);
    if (iVar2 == 0) {
      FUN_10027c30(1,1);
    }
    iVar3 = FUN_10052a10(uVar1 + param_2);
    if (uVar1 != 0) {
      FUN_1002c3b0(param_1,(iVar4 + -1) * param_2 + 0x200,iVar3,uVar1,0);
      FUN_10024150(param_1,param_2,param_7,iVar4,uVar1 / param_2);
    }
    FUN_1006cd50(iVar3 + uVar1,param_2);
    FUN_1002c440(param_1,(iVar2 + -1) * param_2 + 0x200,iVar3,uVar1 + param_2,0);
    *param_3 = iVar2;
    iVar5 = param_3[1];
    FUN_10052c10(iVar3);
  }
  if (iVar5 != 0) {
    iVar4 = FUN_1002c3b0(param_1,(iVar2 + -1) * param_2 + (iVar5 + -1) * 8 + 0x200,&local_38,8,0);
    if (iVar4 != 8) {
      FUN_10027c30(1,9);
    }
    if (param_5 <= local_38) {
      FUN_10027c30(1,9);
    }
  }
  local_38 = param_5;
  local_34 = param_6;
  iVar2 = FUN_1002c440(param_1,(iVar2 + -1) * param_2 + iVar5 * 8 + 0x200,&local_38,8,0);
  if (iVar2 != 8) {
    FUN_10027c30(1,9);
  }
  param_3[1] = iVar5 + 1;
  FUN_1002c440(param_1,param_4,param_3,8,0);
  return;
}

