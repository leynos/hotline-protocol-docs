
void FUN_1006d440(undefined4 *param_1,undefined4 param_2,undefined4 param_3)

{
  if (param_1 == (undefined4 *)0x0) {
    FUN_10027c30(1,2);
  }
  if (*(char *)(param_1 + 1) == '\0') {
    FUN_10073b50(*param_1,param_2,param_3,param_1);
  }
  else {
    FUN_1006fa10(*param_1,param_2,param_3,param_1);
  }
  return;
}

