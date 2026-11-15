
void FUN_10009930(undefined1 *param_1)

{
  *(undefined4 *)(param_1 + 0xc) = 0;
  *(undefined4 *)(param_1 + 8) = 0;
  *(undefined4 *)(param_1 + 4) = 0xffffffff;
  *param_1 = 1;
  param_1[0x10] = 0;
  param_1[0x31] = 0;
  return;
}

