
undefined4 FUN_10025eb0(int param_1,uint param_2)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  
  if ((param_2 == 0) || (*(int *)(param_1 + 0x1c) == 0)) {
    return 0;
  }
  iVar4 = *(int *)(param_1 + 0x1c);
  uVar3 = 0;
  uVar2 = *(int *)(param_1 + 0x24) - 1;
  while (uVar3 != uVar2) {
    uVar1 = uVar3 + uVar2 >> 1;
    if (*(uint *)(iVar4 + ((uVar3 + uVar2) * 4 & 0xfffffff8) + 4) < param_2) {
      uVar3 = uVar1 + 1;
    }
    else {
      uVar2 = uVar1;
    }
  }
  if (param_2 == *(uint *)(iVar4 + uVar3 * 8 + 4)) {
    return *(undefined4 *)(iVar4 + uVar3 * 8);
  }
  return 0;
}

