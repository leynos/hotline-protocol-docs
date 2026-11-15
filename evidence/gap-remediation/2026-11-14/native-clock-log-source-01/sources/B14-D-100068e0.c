
void FUN_100068e0(undefined4 param_1,int param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6,undefined4 param_7,undefined4 param_8)

{
  undefined4 uVar1;
  undefined1 *puVar2;
  undefined4 uStack00000020;
  undefined4 uStack00000024;
  undefined4 uStack00000028;
  undefined4 uStack0000002c;
  undefined4 uStack00000030;
  undefined4 uStack00000034;
  undefined1 local_210;
  undefined1 auStack_20f [255];
  undefined1 local_110;
  undefined1 auStack_10f [259];
  
  puVar2 = (undefined1 *)0x1008fdf8;
  uStack00000020 = param_3;
  uStack00000024 = param_4;
  uStack00000028 = param_5;
  uStack0000002c = param_6;
  uStack00000030 = param_7;
  uStack00000034 = param_8;
  local_110 = FUN_100541c0(auStack_10f,0xff,param_3,&uStack00000024);
  if (((param_2 != 0) &&
      (puVar2 = (undefined1 *)(param_2 + 0x38), *(char *)(param_2 + 0x38) == '\0')) &&
     (*(int *)(param_2 + 4) != 0)) {
    uVar1 = FUN_10058270(*(undefined4 *)(param_2 + 4));
    local_210 = FUN_1006d550(uVar1,auStack_20f,0xff);
    puVar2 = &local_210;
  }
  FUN_10006a70(param_1,puVar2,&local_110);
  return;
}

