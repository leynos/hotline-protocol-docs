
void FUN_10058d90(int param_1)

{
  int iVar1;
  int *piVar2;
  
  iVar1 = FUN_10052b70(0x20);
  piVar2 = *(int **)(param_1 + 0x10);
  if (piVar2 == (int *)0x0) {
    *(int *)(param_1 + 0x10) = iVar1;
  }
  else {
    for (; *piVar2 != 0; piVar2 = (int *)*piVar2) {
    }
    *piVar2 = iVar1;
  }
  return;
}

