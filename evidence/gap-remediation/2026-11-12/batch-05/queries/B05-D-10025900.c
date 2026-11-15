
undefined4 * FUN_10025900(undefined4 *param_1,int param_2)

{
  undefined4 *puVar1;
  undefined1 *puVar2;
  
  *param_1 = &PTR_PTR_100938a0;
  param_1[2] = param_2 * 0x32 + 0xc;
  puVar1 = (undefined4 *)FUN_10052a10();
  param_1[1] = puVar1;
  param_1[6] = 0;
  param_1[3] = 0;
  param_1[4] = puVar1 + 1;
  *puVar1 = 0;
  puVar1 = (undefined4 *)param_1[4];
  param_1[4] = puVar1 + 1;
  *puVar1 = 0;
  puVar2 = (undefined1 *)param_1[4];
  param_1[4] = puVar2 + 1;
  *puVar2 = 0;
  puVar2 = (undefined1 *)param_1[4];
  param_1[4] = puVar2 + 1;
  *puVar2 = 0;
  param_1[5] = 0;
  param_1[9] = 0;
  param_1[8] = 0;
  param_1[7] = 0;
  return param_1;
}

