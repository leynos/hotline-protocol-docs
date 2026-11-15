
uint FUN_1002c070(int param_1,uint param_2)

{
  short sVar2;
  int iVar1;
  uint uVar3;
  
  sVar2 = FUN_1002a9f0();
  if (sVar2 < 0xa00) {
    if (0x1f < param_2) {
      iVar1 = FUN_1006ced0(0x2e,param_1,param_2);
      if (iVar1 != 0) {
        uVar3 = (param_1 + param_2) - iVar1;
        if (0x1e < uVar3) {
          uVar3 = 0x1e;
        }
        FUN_100539c0((param_1 + 0x1f) - uVar3);
      }
      param_2 = 0x1f;
    }
  }
  else if (0xff < param_2) {
    param_2 = 0xff;
  }
  FUN_1002f0c0(param_1,param_2);
  return param_2;
}

