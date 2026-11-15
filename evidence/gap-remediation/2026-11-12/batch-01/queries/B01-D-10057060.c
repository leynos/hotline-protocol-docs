
void FUN_10057060(int param_1)

{
  undefined2 uVar1;
  undefined2 uVar2;
  ushort uVar3;
  ushort uVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  ushort *puVar8;
  ushort *puVar9;
  undefined2 *puVar10;
  undefined2 *puVar11;
  uint uVar12;
  
  if (*(int *)(param_1 + 0xc) == 0) {
    return;
  }
  uVar6 = *(uint *)(param_1 + 0x10);
  iVar5 = *(int *)(param_1 + 0xc);
  if (uVar6 < 2) {
    return;
  }
  uVar7 = (uVar6 >> 1) + 1;
  puVar11 = (undefined2 *)(iVar5 + (uVar6 >> 1) * 4);
  puVar10 = (undefined2 *)(iVar5 + (uVar6 - 1) * 4);
  do {
    if (uVar7 < 2) {
      uVar1 = *puVar11;
      uVar2 = puVar11[1];
      *puVar11 = *puVar10;
      puVar11[1] = puVar10[1];
      *puVar10 = uVar1;
      puVar10[1] = uVar2;
      uVar6 = uVar6 - 1;
      if (uVar6 == 1) {
        return;
      }
      puVar10 = puVar10 + -2;
    }
    else {
      uVar7 = uVar7 - 1;
      puVar11 = puVar11 + -2;
    }
    puVar9 = (ushort *)(iVar5 + (uVar7 - 1) * 4);
    uVar12 = uVar7;
    while (uVar12 << 1 <= uVar6) {
      uVar12 = uVar12 * 2;
      puVar8 = (ushort *)(iVar5 + (uVar12 - 1) * 4);
      if ((uVar12 < uVar6) && (*puVar8 < puVar8[2])) {
        uVar12 = uVar12 + 1;
        puVar8 = puVar8 + 2;
      }
      if (*puVar8 <= *puVar9) break;
      uVar3 = *puVar9;
      uVar4 = puVar9[1];
      *puVar9 = *puVar8;
      puVar9[1] = puVar8[1];
      *puVar8 = uVar3;
      puVar8[1] = uVar4;
      puVar9 = puVar8;
    }
  } while( true );
}

