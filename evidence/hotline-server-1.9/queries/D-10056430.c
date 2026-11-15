
undefined4 FUN_10056430(undefined4 *param_1,ushort param_2)

{
  undefined4 uVar1;
  
  if ((param_1 != (undefined4 *)0x0) && (param_2 != 0)) {
    if (param_1[2] == 0) {
      FUN_10056e20(param_1);
    }
    if ((uint)param_2 <= (uint)param_1[4]) {
      uVar1 = FUN_10053910(*param_1,param_1[1] + *(int *)(param_1[2] + (uint)param_2 * 4 + -4));
      return uVar1;
    }
  }
  return 0;
}

