
uint FUN_10056c00(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  uint local_10 [4];
  
  iVar1 = FUN_100565b0(param_1,param_2,0,local_10,4);
  if (iVar1 != 3) {
    if (iVar1 < 3) {
      if (iVar1 == 1) {
        return local_10[0] >> 0x18;
      }
      if (0 < iVar1) {
        return local_10[0] >> 0x10;
      }
    }
    else if (iVar1 < 5) {
      return local_10[0];
    }
  }
  return 0;
}

