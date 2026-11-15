
void FUN_10025f40(int param_1,undefined4 param_2,uint param_3)

{
  bool bVar1;
  uint uVar2;
  undefined4 *puVar3;
  undefined4 uVar4;
  int iVar5;
  undefined4 *puVar6;
  uint uVar7;
  int iVar8;
  uint uVar9;
  
  iVar8 = *(int *)(param_1 + 0x1c);
  uVar9 = 0;
  if ((*(int *)(param_1 + 0x24) != 0) && (*(int *)(param_1 + 0x1c) != 0)) {
    uVar7 = *(uint *)(param_1 + 0x24);
    while (uVar9 != uVar7) {
      uVar2 = uVar9 + uVar7 >> 1;
      if (*(uint *)(iVar8 + ((uVar9 + uVar7) * 4 & 0xfffffff8) + 4) < param_3) {
        uVar9 = uVar2 + 1;
      }
      else {
        uVar7 = uVar2;
      }
    }
    if ((uint)((*(int *)(param_1 + 0x24) + 1) * 8) <= *(uint *)(param_1 + 0x20)) goto LAB_10026014;
  }
  iVar8 = (*(int *)(param_1 + 0x24) + 10) * 8;
  uVar4 = *(undefined4 *)(param_1 + 0x1c);
  *(undefined4 *)(param_1 + 0x1c) = 0;
  iVar5 = FUN_10052ff0(uVar4,iVar8);
  *(int *)(param_1 + 0x1c) = iVar5;
  if (iVar5 == 0) {
    FUN_10027c30(3,0x65);
  }
  *(int *)(param_1 + 0x20) = iVar8;
  iVar8 = *(int *)(param_1 + 0x1c);
LAB_10026014:
  puVar6 = (undefined4 *)(iVar8 + uVar9 * 8);
  iVar5 = *(int *)(param_1 + 0x24) - uVar9;
  puVar3 = puVar6;
  while( true ) {
    bVar1 = iVar5 == 0;
    iVar5 = iVar5 + -1;
    if (bVar1) break;
    puVar3[2] = *puVar6;
    puVar3[3] = puVar6[1];
    puVar6 = puVar6 + 2;
    puVar3 = puVar3 + 2;
  }
  *(undefined4 *)(iVar8 + uVar9 * 8) = param_2;
  *(uint *)(iVar8 + uVar9 * 8 + 4) = param_3;
  *(int *)(param_1 + 0x24) = *(int *)(param_1 + 0x24) + 1;
  return;
}

