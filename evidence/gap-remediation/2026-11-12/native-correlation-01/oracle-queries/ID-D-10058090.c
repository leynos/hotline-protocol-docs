
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 * FUN_10058090(undefined4 param_1,undefined4 param_2,undefined4 param_3)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  
  puVar1 = (undefined4 *)FUN_10052b70(0x50);
  *puVar1 = 0;
  uVar2 = FUN_1006d340(param_1,param_2,param_3);
  *puVar1 = uVar2;
  FUN_1006d440(uVar2,PTR_PTR_1008934c,puVar1);
  puVar1[0xf] = _DAT_10089420;
  return puVar1;
}

