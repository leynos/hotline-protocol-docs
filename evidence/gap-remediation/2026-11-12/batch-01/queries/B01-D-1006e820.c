
uint FUN_1006e820(ushort *param_1,uint param_2,undefined4 param_3,uint param_4,uint *param_5,
                 undefined4 *param_6)

{
  uint uVar1;
  ushort *puVar2;
  ushort *puVar3;
  
  if (param_6 != (undefined4 *)0x0) {
    *param_6 = 0;
  }
  if ((param_1 == (ushort *)0x0) || (param_2 < 6)) {
    uVar1 = 0;
  }
  else {
    puVar2 = (ushort *)((int)param_1 + param_2);
    uVar1 = (uint)*param_1;
    puVar3 = param_1 + 1;
    if (*param_1 == 0) {
      uVar1 = 0;
    }
    else {
      while (uVar1 = uVar1 - 1, uVar1 != 0) {
        puVar3 = puVar3 + 1;
        if (puVar2 <= puVar3) {
          return 0;
        }
        puVar3 = (ushort *)((int)puVar3 + *(byte *)puVar3 + 1);
      }
      if (param_5 != (uint *)0x0) {
        if (puVar2 < puVar3 + 1) {
          return 0;
        }
        *param_5 = (uint)*puVar3;
      }
      if (puVar3 + 1 < puVar2) {
        uVar1 = (uint)*(byte *)(puVar3 + 1);
        if (puVar2 < (byte *)((int)puVar3 + 3) + uVar1) {
          uVar1 = 0;
        }
        else {
          if (param_4 < uVar1) {
            uVar1 = param_4;
          }
          FUN_100539c0(param_3,(byte *)((int)puVar3 + 3),uVar1);
          if (param_6 != (undefined4 *)0x0) {
            *param_6 = puVar3 + 1;
          }
        }
      }
      else {
        uVar1 = 0;
      }
    }
  }
  return uVar1;
}

