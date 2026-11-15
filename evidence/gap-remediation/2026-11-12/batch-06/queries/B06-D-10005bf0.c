
void FUN_10005bf0(int param_1)

{
  int iVar1;
  
  if (*(int *)(param_1 + 0x98) == 0) {
    iVar1 = FUN_1006d260(0x14);
    if (iVar1 != 0) {
      FUN_10021bf0(iVar1);
    }
    *(int *)(param_1 + 0x98) = iVar1;
    FUN_1003a510(*(undefined4 *)(iVar1 + 0xc),1);
  }
  return;
}

