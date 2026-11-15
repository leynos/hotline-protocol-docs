
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 * FUN_100738b0(undefined4 param_1,undefined4 param_2)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  
  uVar3 = _DAT_100893b0;
  puVar1 = (undefined4 *)FUN_10052b70(100);
  puVar1[10] = param_1;
  puVar1[0xb] = param_2;
  uVar2 = FUN_1006f720(param_1,param_2);
  *puVar1 = uVar2;
  FUN_1006fa10(uVar2,uVar3,puVar1,0);
  *(undefined1 *)(puVar1 + 2) = 1;
  uVar2 = FUN_1006f720(puVar1[10],puVar1[0xb]);
  puVar1[1] = uVar2;
  FUN_1006fa10(uVar2,uVar3,puVar1,0);
  *(undefined1 *)((int)puVar1 + 9) = 1;
  *(undefined1 *)((int)puVar1 + 10) = 2;
  uVar3 = FUN_1002a260(_DAT_100893ac,puVar1);
  puVar1[7] = uVar3;
  FUN_1006f2e0(puVar1 + 0xc);
  FUN_1006f350(puVar1 + 0xc,puVar1 + 0xc);
  FUN_100554e0(&DAT_10096bdc,puVar1);
  return puVar1;
}

