
void FUN_100048b0(undefined4 param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  char cVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  
  iVar2 = *(int *)(param_2 + 4);
  iVar3 = *(int *)(param_2 + 8);
  for (iVar4 = 0; iVar4 != iVar3; iVar4 = iVar4 + 1) {
    iVar5 = *(int *)(iVar2 + iVar4 * 4);
    cVar1 = FUN_10058600(*(undefined4 *)(iVar5 + 4));
    if (cVar1 != '\0') {
      FUN_10058ca0(*(undefined4 *)(iVar5 + 4),param_3,param_4);
    }
  }
  return;
}

