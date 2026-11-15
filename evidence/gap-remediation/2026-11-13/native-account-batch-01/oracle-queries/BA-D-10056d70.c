
void FUN_10056d70(int *param_1,int param_2,int param_3)

{
  if ((param_1 == (int *)0x0) || (param_2 == 0)) {
    FUN_10027c30(1,2);
  }
  FUN_10052e90(*param_1);
  FUN_10052c10(param_1[2]);
  FUN_10052c10(param_1[3]);
  param_1[2] = 0;
  param_1[3] = 0;
  param_1[4] = 0;
  *(undefined2 *)(param_1 + 6) = 0;
  *param_1 = param_2;
  param_1[1] = param_3;
  return;
}

