
void FUN_10058160(undefined4 *param_1)

{
  int *piVar1;
  int iVar2;
  
  if (param_1 != (undefined4 *)0x0) {
    if (param_1[1] != 0) {
      FUN_10028ea0(param_1[1],param_1[2],param_1);
    }
    piVar1 = (int *)param_1[4];
    while (piVar1 != (int *)0x0) {
      iVar2 = *piVar1;
      FUN_10052e90(piVar1[1]);
      FUN_10052c10(piVar1);
      piVar1 = (int *)iVar2;
    }
    FUN_10052e90(param_1[8]);
    FUN_1002a370(param_1[0xe]);
    FUN_1006d3e0(*param_1);
    FUN_10052c10(param_1);
  }
  return;
}

