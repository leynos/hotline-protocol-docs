
int FUN_100565b0(undefined4 *param_1,ushort param_2,uint param_3,undefined4 param_4,int param_5)

{
  undefined4 uVar1;
  int iVar2;
  uint uVar3;
  
  if ((param_1 != (undefined4 *)0x0) && (param_2 != 0)) {
    if (param_1[2] == 0) {
      FUN_10056e20(param_1);
    }
    if ((uint)param_2 <= (uint)param_1[4]) {
      uVar1 = *param_1;
      iVar2 = FUN_10053290();
      iVar2 = iVar2 + param_1[1] + *(int *)(param_1[2] + (uint)param_2 * 4 + -4);
      uVar3 = (uint)*(ushort *)(iVar2 + 2);
      if (param_3 < uVar3) {
        if (uVar3 < param_3 + param_5) {
          param_5 = uVar3 - param_3;
        }
        FUN_100539c0(param_4,iVar2 + 4 + param_3,param_5);
        FUN_10053310(uVar1);
        return param_5;
      }
      FUN_10053310(uVar1);
    }
  }
  return 0;
}

