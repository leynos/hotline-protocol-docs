
int FUN_1000e690(int param_1,int param_2)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  char *pcVar4;
  int *piVar5;
  undefined4 *puVar6;
  
  iVar2 = *(int *)(param_1 + 0x48);
  if (iVar2 != 0) {
    piVar5 = *(int **)(param_1 + 0x44);
    while( true ) {
      bVar1 = iVar2 == 0;
      iVar2 = iVar2 + -1;
      if (bVar1) break;
      iVar3 = *piVar5;
      piVar5 = piVar5 + 1;
      if (*(int *)(iVar3 + 0xc) == param_2) {
        return iVar3;
      }
    }
  }
  iVar2 = *(int *)(param_1 + 0x54);
  if (iVar2 != 0) {
    puVar6 = *(undefined4 **)(param_1 + 0x50);
    while (bVar1 = iVar2 != 0, iVar2 = iVar2 + -1, bVar1) {
      pcVar4 = (char *)*puVar6;
      puVar6 = puVar6 + 1;
      if ((*pcVar4 == '\0') && (*(int *)(*(int *)(pcVar4 + 8) + 0xc) == param_2)) {
        return *(int *)(pcVar4 + 8);
      }
    }
  }
  return 0;
}

