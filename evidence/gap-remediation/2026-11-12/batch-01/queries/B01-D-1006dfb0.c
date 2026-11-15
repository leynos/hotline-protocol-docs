
void FUN_1006dfb0(undefined4 *param_1,undefined4 param_2,undefined4 param_3)

{
  if (param_1 == (undefined4 *)0x0) {
    FUN_10027c30(1,2);
  }
  if (*(char *)(param_1 + 1) == '\0') {
    FUN_10074710(*param_1,param_2,param_3);
  }
  else {
    FUN_10071430(*param_1,param_2,param_3);
  }
  return;
}

