
int FUN_10025d80(int param_1,int *param_2)

{
  int iVar1;
  int iVar2;
  
  if (*(int *)(param_1 + 4) == 0) {
    iVar1 = 0;
  }
  else {
    iVar2 = *(int *)(param_1 + 0x10) - *(int *)(param_1 + 4);
    iVar1 = FUN_10052ff0(*(undefined4 *)(param_1 + 4),iVar2);
    *(undefined4 *)(iVar1 + 4) = *(undefined4 *)(param_1 + 0x14);
    *(undefined4 *)(param_1 + 8) = 0;
    *(undefined4 *)(param_1 + 4) = 0;
    *(undefined4 *)(param_1 + 0x18) = 0;
    *param_2 = iVar2;
  }
  return iVar1;
}

