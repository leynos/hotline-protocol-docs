
void FUN_10016ad0(undefined4 param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  int iVar1;
  
  iVar1 = FUN_10057d00();
  if (0x3c < (uint)(iVar1 - *(int *)(param_2 + 0xa8))) {
    *(int *)(param_2 + 0xa8) = iVar1;
    *(undefined2 *)(param_2 + 0x146) = 0;
  }
  if (*(ushort *)(param_2 + 0x146) < 0x1a) {
    *(short *)(param_2 + 0x146) = *(short *)(param_2 + 0x146) + 1;
    FUN_10004d50(param_1,param_2,param_4,0);
  }
  else {
    FUN_100583b0(*(undefined4 *)(param_2 + 4));
    FUN_100063c0(param_1,*(undefined4 *)(param_2 + 0x10));
    FUN_100068e0(param_1,param_2,s_Autobanned_for_flooding_100905fd);
  }
  return;
}

