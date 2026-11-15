
void FUN_10058a10(int param_1,undefined4 param_2)

{
  if (param_1 == 0) {
    FUN_10027c30(1,2);
  }
  if (*(int *)(param_1 + 0xc) != 0) {
    *(undefined4 *)(*(int *)(param_1 + 0xc) + 0x14) = param_2;
  }
  return;
}

