
undefined4 * FUN_100195e0(undefined4 *param_1,short param_2)

{
  if (param_1 != (undefined4 *)0x0) {
    *param_1 = &PTR_PTR_10095de8;
    param_1[0xd] = &PTR_PTR_10095ec0;
    FUN_10055ba0(param_1 + 0x15,0xffffffff);
    if (param_1 != (undefined4 *)0x0) {
      *param_1 = &PTR_PTR_10095600;
      param_1[0xd] = &PTR_PTR_100956d8;
      if (param_1 != (undefined4 *)0x0) {
        *param_1 = &PTR_PTR_10095710;
        FUN_10059670(param_1,0);
      }
    }
    if (0 < param_2) {
      FUN_1006d290(param_1);
    }
  }
  return param_1;
}

