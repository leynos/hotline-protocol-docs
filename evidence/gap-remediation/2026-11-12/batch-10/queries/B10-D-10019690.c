
undefined4 * FUN_10019690(undefined4 *param_1,short param_2)

{
  uint uVar1;
  
  if (param_1 != (undefined4 *)0x0) {
    *param_1 = &PTR_PTR_100923a8;
    param_1[0xd] = &PTR_PTR_10092480;
    uVar1 = 0;
    while (uVar1 = uVar1 + 1, uVar1 <= (uint)param_1[0x1d]) {
      FUN_10052c10(*(undefined4 *)(param_1[0x1c] + uVar1 * 4 + -4));
    }
    FUN_10055880(param_1 + 0x1c);
    FUN_100361f0(param_1[0x19]);
    FUN_100361f0(param_1[0x1a]);
    FUN_100361f0(param_1[0x1b]);
    if (param_1 != (undefined4 *)0xffffff90) {
      FUN_10055480(param_1 + 0x1c,0);
    }
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
    }
    if (0 < param_2) {
      FUN_1006d290(param_1);
    }
  }
  return param_1;
}

