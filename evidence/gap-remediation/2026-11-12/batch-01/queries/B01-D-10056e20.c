
void FUN_10056e20(int *param_1)

{
  ushort uVar1;
  ushort *puVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  ushort *puVar7;
  int unaff_r30;
  ushort *local_40;
  
  if (*param_1 != 0) {
    FUN_10052c10(param_1[2]);
    FUN_10052c10(param_1[3]);
    param_1[2] = 0;
    param_1[3] = 0;
    param_1[4] = 0;
    *(undefined2 *)(param_1 + 6) = 0;
    iVar6 = *param_1;
    uVar3 = FUN_10052f80(iVar6);
    local_40 = (ushort *)FUN_10053290(iVar6);
    puVar7 = (ushort *)((int)local_40 + uVar3);
    uVar4 = param_1[1];
    if (uVar4 != 0) {
      local_40 = (ushort *)((int)local_40 + uVar4);
      if (uVar4 < uVar3) {
        uVar3 = uVar3 - uVar4;
      }
      else {
        uVar3 = 0;
      }
    }
    puVar2 = local_40;
    if (uVar3 < 3) {
      uVar3 = 0;
    }
    else {
      uVar3 = (uint)*local_40;
    }
    local_40 = local_40 + 1;
    iVar5 = FUN_10052b70((uVar3 + 1) * 4);
    param_1[2] = iVar5;
    if (uVar3 != 0) {
      unaff_r30 = FUN_10052b70(uVar3 << 2);
      param_1[3] = unaff_r30;
    }
    uVar4 = 0;
    for (; ((uVar4 < uVar3 && (local_40 + 2 <= puVar7)) &&
           (uVar1 = local_40[1], (ushort *)((int)local_40 + uVar1 + 4) <= puVar7));
        local_40 = (ushort *)((int)local_40 + uVar1 + 4)) {
      *(int *)(iVar5 + uVar4 * 4) = (int)local_40 - (int)puVar2;
      *(ushort *)(unaff_r30 + uVar4 * 4) = *local_40;
      *(short *)(unaff_r30 + uVar4 * 4 + 2) = (short)uVar4;
      uVar4 = uVar4 + 1;
    }
    *(int *)(iVar5 + uVar4 * 4) = (int)local_40 - (int)puVar2;
    param_1[4] = uVar4;
    FUN_10057060(param_1);
    FUN_10053310(iVar6);
  }
  return;
}

