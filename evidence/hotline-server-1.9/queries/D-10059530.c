
undefined4 * FUN_10059530(undefined4 *param_1,int param_2,undefined4 *param_3)

{
  *param_1 = &PTR_PTR_10094a98;
  param_1[2] = *param_3;
  param_1[3] = param_3[1];
  param_1[4] = param_3[2];
  param_1[5] = param_3[3];
  param_1[7] = 0;
  param_1[6] = 0;
  *(undefined1 *)(param_1 + 10) = 0;
  *(undefined1 *)((int)param_1 + 0x29) = 1;
  *(byte *)((int)param_1 + 0x2b) = *(byte *)((int)param_1 + 0x2b) & 0x1f;
  *(undefined1 *)((int)param_1 + 0x2a) = 1;
  param_1[1] = 0;
  if (param_2 != 0) {
    FUN_10082630(param_2,param_1);
    param_1[1] = param_2;
  }
  param_1[8] = 0;
  param_1[9] = 0;
  return param_1;
}

