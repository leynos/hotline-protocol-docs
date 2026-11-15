
undefined4 * FUN_10059670(undefined4 *param_1,short param_2)

{
  if (param_1 != (undefined4 *)0x0) {
    *param_1 = &PTR_PTR_10094a98;
    FUN_10028ea0(PTR_PTR_1008906c,param_1,0);
    if (param_1[1] != 0) {
      if ((*(byte *)((int)param_1 + 0x2b) >> 5 & 1) != 0) {
        FUN_10082630(param_1[1],param_1);
      }
      FUN_10082630(param_1[1],param_1);
    }
    if (param_1[8] != 0) {
      FUN_10052c10(param_1[8]);
    }
    if (param_1[9] != 0) {
      FUN_10052c10(param_1[9]);
    }
    if (0 < param_2) {
      FUN_1006d290(param_1);
    }
  }
  return param_1;
}

