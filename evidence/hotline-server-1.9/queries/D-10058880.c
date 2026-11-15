
int * FUN_10058880(int param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  
  if (param_1 == 0) {
    FUN_10027c30(1,2);
  }
  FUN_100590e0(param_1);
  iVar1 = FUN_10058e80(param_1,param_2,param_3);
  if (iVar1 == 0) {
    piVar2 = (int *)0x0;
  }
  else {
    piVar2 = (int *)FUN_10052b70(0x18);
    *piVar2 = param_1;
    piVar2[2] = *(int *)(param_1 + 0x3c);
    piVar2[4] = iVar1;
    iVar3 = FUN_10058d90(param_1);
    piVar2[3] = iVar3;
    *(undefined2 *)(iVar3 + 0x1a) = 2;
    *(undefined4 *)(iVar3 + 0x10) = *(undefined4 *)(iVar1 + 0x10);
    *(byte *)(iVar1 + 0x1c) = *(byte *)(iVar1 + 0x1c) & 0xbf | 0x40;
  }
  return piVar2;
}

