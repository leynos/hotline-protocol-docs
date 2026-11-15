
int FUN_10079e30(undefined4 param_1,int param_2)

{
  int iVar1;
  undefined4 *puVar2;
  uint uVar3;
  int iVar4;
  
  uVar3 = param_2 + 7U & 0xfffffff8;
  iVar1 = FUN_10079cb0(param_1,uVar3);
  if (iVar1 == 0) {
    iVar1 = 0;
  }
  else {
    iVar4 = (uVar3 >> 2) + 1;
    puVar2 = (undefined4 *)(iVar1 + -4);
    while( true ) {
      iVar4 = iVar4 + -1;
      if (iVar4 == 0) break;
      puVar2 = puVar2 + 1;
      *puVar2 = 0;
    }
  }
  return iVar1;
}

