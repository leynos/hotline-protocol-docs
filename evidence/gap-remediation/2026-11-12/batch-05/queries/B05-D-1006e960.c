
uint FUN_1006e960(ushort *param_1,uint param_2)

{
  uint uVar1;
  byte bVar2;
  uint uVar3;
  ushort *puVar4;
  ushort *puVar5;
  ushort *puVar6;
  ushort local_820;
  ushort local_81e [1027];
  
  if (0x800 < param_2) {
    FUN_10027c30(1,0xb);
  }
  if (1 < param_2) {
    uVar3 = (uint)*param_1;
    local_820 = *param_1;
    puVar4 = param_1 + 1;
    puVar6 = local_81e;
    if (uVar3 << 2 <= (int)param_1 + (param_2 - (int)puVar4)) {
      while (uVar1 = uVar3 & 0xffff, uVar3 = uVar3 - 1, uVar1 != 0) {
        *puVar6 = *puVar4;
        puVar5 = puVar6 + 1;
        FUN_1007c240(puVar5,puVar4 + 1);
        uVar1 = (uint)*(byte *)(puVar4 + 1);
        if ((int)param_1 + (param_2 - ((int)puVar4 + 3)) < uVar1 + (uVar3 * 4 & 0x3fffc)) {
          return param_2;
        }
        puVar4 = (ushort *)((int)puVar4 + 3 + uVar1);
        bVar2 = FUN_1002c070((int)puVar6 + 3,uVar1,0);
        *(byte *)puVar5 = bVar2;
        puVar6 = (ushort *)((int)puVar5 + bVar2 + 1);
      }
      param_2 = FUN_100539c0(param_1,&local_820,(int)puVar6 - (int)&local_820);
    }
  }
  return param_2;
}

