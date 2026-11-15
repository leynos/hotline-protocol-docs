
bool FUN_1002cac0(short *param_1,short *param_2)

{
  int iVar1;
  bool bVar2;
  
  if ((*(int *)(param_1 + 1) == *(int *)(param_2 + 1)) && (*param_1 == *param_2)) {
    iVar1 = FUN_1007c2b0(param_1 + 3,param_2 + 3);
    bVar2 = iVar1 == 0;
  }
  else {
    bVar2 = false;
  }
  return bVar2;
}

