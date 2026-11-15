
void FUN_10025060(undefined4 param_1,uint param_2,undefined4 param_3,int param_4)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  int local_30;
  int local_2c;
  
  iVar3 = 0x40;
  while ((param_4 != 0 && (bVar1 = iVar3 != 0, iVar3 = iVar3 + -1, bVar1))) {
    iVar2 = FUN_1002c3b0(param_1,(param_4 + -1) * param_2 + 0x200,&local_30,8,0);
    if (iVar2 != 8) {
      FUN_10027c30(1,9);
    }
    FUN_10024150(param_1,param_2,param_3,param_4,(param_2 + local_2c + -1) / param_2);
    param_4 = local_30;
  }
  return;
}

