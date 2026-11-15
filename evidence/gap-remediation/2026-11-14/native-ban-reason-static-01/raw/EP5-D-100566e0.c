
int FUN_100566e0(undefined4 *param_1,undefined4 param_2,uint param_3,undefined4 param_4,int param_5)

{
  char cVar2;
  int iVar1;
  uint uVar3;
  int local_20;
  int local_1c;
  undefined4 local_18;
  
  cVar2 = FUN_100572d0(param_1,param_2,&local_20);
  if (cVar2 != '\0') {
    local_18 = *param_1;
    iVar1 = FUN_10053290();
    uVar3 = (uint)*(ushort *)(iVar1 + local_20 + 2);
    local_1c = iVar1 + local_20 + 4;
    if (param_3 < uVar3) {
      if (uVar3 < param_3 + param_5) {
        param_5 = uVar3 - param_3;
      }
      FUN_100539c0(param_4,local_1c + param_3,param_5);
      FUN_10053310(local_18);
      return param_5;
    }
    FUN_10053310(local_18);
  }
  return 0;
}

