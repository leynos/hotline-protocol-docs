
undefined4 FUN_10057180(int param_1,ushort param_2,uint *param_3,undefined4 param_4,uint param_5)

{
  uint uVar1;
  uint uVar2;
  ushort uVar3;
  ushort *puVar4;
  
  if (param_2 == 0) {
    *param_3 = 0;
    return 0;
  }
  if (*(ushort *)(param_1 + 0x18) == param_2) {
    *param_3 = *(uint *)(param_1 + 0x14);
    return 1;
  }
  puVar4 = *(ushort **)(param_1 + 0xc);
  if ((puVar4 == (ushort *)0x0) || (*(int *)(param_1 + 0x10) == 0)) {
    *param_3 = 0;
    return 0;
  }
  uVar3 = *puVar4;
  if (param_2 == uVar3) {
    *param_3 = 0;
  }
  else {
    if (param_2 < uVar3) {
      *param_3 = 0;
      return 0;
    }
    uVar2 = 1;
    uVar1 = *(int *)(param_1 + 0x10) - 1;
    if (uVar1 == 0) {
      *param_3 = 1;
      return 0;
    }
    while( true ) {
      if (uVar1 < uVar2) {
        if (uVar3 < param_2) {
          param_5 = param_5 + 1;
        }
        *param_3 = param_5;
        return 0;
      }
      param_5 = uVar2 + uVar1 >> 1;
      uVar3 = *(ushort *)((int)puVar4 + ((uVar2 + uVar1) * 2 & 0xfffffffc));
      if (param_2 == uVar3) break;
      if (param_2 < uVar3) {
        uVar1 = param_5 - 1;
      }
      else {
        uVar2 = param_5 + 1;
      }
    }
    *param_3 = param_5;
  }
  *(ushort *)(param_1 + 0x18) = param_2;
  *(uint *)(param_1 + 0x14) = *param_3;
  return 1;
}

