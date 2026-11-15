
void FUN_10027c80(undefined2 *param_1,undefined2 param_2,undefined2 param_3)

{
  *param_1 = param_2;
  param_1[1] = param_3;
  *(char **)(param_1 + 2) = s__SError___10093941 + 10;
  *(undefined4 *)(param_1 + 4) = 0;
  *(byte *)(param_1 + 8) = *(byte *)(param_1 + 8) & 0x3f;
  *(undefined4 *)(param_1 + 6) = 0;
  return;
}

