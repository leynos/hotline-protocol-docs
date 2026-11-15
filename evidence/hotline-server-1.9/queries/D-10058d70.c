
undefined4 FUN_10058d70(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xc) + 1;
  *(int *)(param_1 + 0xc) = iVar1;
  if (iVar1 == 0) {
    *(undefined4 *)(param_1 + 0xc) = 1;
  }
  return *(undefined4 *)(param_1 + 0xc);
}

