
void FUN_10056820(undefined4 *param_1)

{
  if (param_1 == (undefined4 *)0x0) {
    FUN_10027c30(1,2);
  }
  FUN_10052e90(*param_1);
  FUN_10052c10(param_1[2]);
  FUN_10052c10(param_1[3]);
  *param_1 = 0;
  param_1[3] = 0;
  param_1[2] = 0;
  param_1[4] = 0;
  *(undefined2 *)(param_1 + 6) = 0;
  return;
}

