
int FUN_1000ec80(int param_1,int param_2)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  int *piVar4;
  
  iVar2 = *(int *)(param_1 + 0x78);
  if (iVar2 != 0) {
    piVar4 = *(int **)(param_1 + 0x74);
    while (bVar1 = iVar2 != 0, iVar2 = iVar2 + -1, bVar1) {
      iVar3 = *piVar4;
      piVar4 = piVar4 + 1;
      if (*(int *)(iVar3 + 0xc) == param_2) {
        return iVar3;
      }
    }
  }
  return 0;
}

