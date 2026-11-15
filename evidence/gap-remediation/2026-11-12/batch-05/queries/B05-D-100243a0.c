
undefined4 FUN_100243a0(undefined4 param_1,int param_2,int param_3)

{
  int iVar1;
  undefined4 local_10 [4];
  
  if (param_3 == 0) {
    local_10[0] = 0;
  }
  else {
    iVar1 = FUN_1002c3b0(param_1,(param_3 + -1) * param_2 + 0x224,local_10,4,0);
    if (iVar1 != 4) {
      local_10[0] = 0;
    }
  }
  return local_10[0];
}

