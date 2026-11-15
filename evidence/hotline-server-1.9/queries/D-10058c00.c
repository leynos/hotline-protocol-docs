
void FUN_10058c00(undefined4 *param_1,undefined4 param_2)

{
  int iVar1;
  
  if (param_1 == (undefined4 *)0x0) {
    FUN_10027c30(1,2);
  }
  iVar1 = param_1[4];
  FUN_100590e0(*param_1);
  if ((iVar1 == 0) || (*(int *)(iVar1 + 4) == 0)) {
    FUN_10056820(param_2);
  }
  else {
    FUN_10056d70(param_2,*(undefined4 *)(iVar1 + 4),0);
    *(undefined4 *)(iVar1 + 4) = 0;
  }
  return;
}

