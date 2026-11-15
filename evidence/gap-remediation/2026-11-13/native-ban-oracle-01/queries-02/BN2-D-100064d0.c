
void FUN_100064d0(int param_1)

{
  bool bVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  
  uVar2 = *(uint *)(param_1 + 0x440);
  if (uVar2 != 0) {
    uVar4 = FUN_10057d00();
    for (uVar5 = 1; uVar5 <= uVar2; uVar5 = uVar5 + 1) {
      bVar1 = false;
      if (uVar5 != 0) {
        if (uVar5 <= *(uint *)(param_1 + 0x440)) {
          bVar1 = true;
        }
      }
      if (bVar1) {
        iVar3 = *(int *)(*(int *)(param_1 + 0x43c) + uVar5 * 4 + -4);
      }
      else {
        iVar3 = 0;
      }
      if (*(uint *)(iVar3 + 4) <= uVar4) {
        FUN_10055770(param_1 + 0x43c,uVar5);
        FUN_1006d290(iVar3);
      }
    }
  }
  return;
}

