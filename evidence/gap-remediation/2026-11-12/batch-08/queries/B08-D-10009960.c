
undefined4 FUN_10009960(int param_1,uint param_2)

{
  if (param_2 < *(uint *)(param_1 + 8)) {
    return 0;
  }
  if (*(uint *)(param_1 + 0xc) < param_2) {
    return 0;
  }
  return 1;
}

