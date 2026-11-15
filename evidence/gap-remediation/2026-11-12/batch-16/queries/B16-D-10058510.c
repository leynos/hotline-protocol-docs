
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

int * FUN_10058510(undefined4 *param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  int *piVar2;
  
  if (param_1 == (undefined4 *)0x0) {
    FUN_10027c30(1,2);
  }
  iVar1 = FUN_1006dcd0(*param_1,param_2,param_3);
  if (iVar1 == 0) {
    piVar2 = (int *)0x0;
  }
  else {
    piVar2 = (int *)FUN_10052b70(0x50);
    *piVar2 = iVar1;
    FUN_1006d440(iVar1,PTR_PTR_1008934c,piVar2);
    piVar2[0xf] = _DAT_10089420;
  }
  return piVar2;
}

