
uint FUN_10056550(int *param_1)

{
  uint uVar1;
  
  if ((param_1 == (int *)0x0) || (*param_1 == 0)) {
    uVar1 = 0;
  }
  else {
    if (param_1[2] == 0) {
      FUN_10056e20(param_1);
    }
    uVar1 = param_1[4] & 0xffff;
  }
  return uVar1;
}

