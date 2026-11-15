
int FUN_1002d7b0(int param_1)

{
  int iVar1;
  
  if (param_1 == 0) {
    FUN_10027c30(1,2);
  }
  if (*(int *)(param_1 + 0x48) == 0) {
    FUN_10027c30(1,3);
  }
  iVar1 = *(int *)(param_1 + 0x48);
  return *(int *)(iVar1 + 0x54) + *(int *)(iVar1 + 0x34) + *(int *)(iVar1 + 0x44) + 0x48;
}

