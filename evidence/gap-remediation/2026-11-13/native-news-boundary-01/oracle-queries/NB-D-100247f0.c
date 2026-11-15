
int FUN_100247f0(undefined4 param_1,int param_2,int param_3,int param_4)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int local_30 [7];
  
  iVar4 = 100;
  local_30[0] = param_3;
  while ((iVar2 = local_30[0], local_30[0] != 0 && (bVar1 = iVar4 != 0, iVar4 = iVar4 + -1, bVar1)))
  {
    iVar3 = FUN_1002c3b0(param_1,param_2 * (local_30[0] + -1) + param_4 + 0x200,local_30,4,0);
    param_3 = iVar2;
    if (iVar3 != 4) {
      FUN_10027c30(1,9);
    }
  }
  return param_3;
}

