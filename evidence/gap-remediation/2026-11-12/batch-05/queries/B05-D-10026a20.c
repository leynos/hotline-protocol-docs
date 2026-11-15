
int FUN_10026a20(int param_1)

{
  uint *puVar1;
  int iVar2;
  char cVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  uint uVar14;
  uint uVar15;
  uint uVar16;
  undefined4 local_50;
  undefined4 local_4c [5];
  
  iVar4 = 1;
  uVar5 = 0;
  while (uVar5 = uVar5 + 1, uVar5 <= *(uint *)(param_1 + 0x10)) {
    puVar1 = *(uint **)(*(int *)(param_1 + 0xc) + uVar5 * 4 + -4);
    if (puVar1[1] == 0) {
      uVar6 = (-*puVar1 | *puVar1) >> 0x1f;
    }
    else {
      uVar8 = puVar1[1];
      uVar6 = 1;
      uVar11 = 0;
      while (uVar11 = uVar11 + 1, uVar11 <= *(uint *)(uVar8 + 0x10)) {
        puVar1 = *(uint **)(*(int *)(uVar8 + 0xc) + uVar11 * 4 + -4);
        if (puVar1[1] == 0) {
          uVar14 = (-*puVar1 | *puVar1) >> 0x1f;
        }
        else {
          uVar15 = puVar1[1];
          uVar14 = 1;
          uVar16 = 0;
          while (uVar16 = uVar16 + 1, uVar16 <= *(uint *)(uVar15 + 0x10)) {
            puVar1 = *(uint **)(*(int *)(uVar15 + 0xc) + uVar16 * 4 + -4);
            if (puVar1[1] == 0) {
              uVar10 = (-*puVar1 | *puVar1) >> 0x1f;
            }
            else {
              uVar12 = puVar1[1];
              uVar10 = 1;
              uVar13 = 0;
              while (uVar13 = uVar13 + 1, uVar13 <= *(uint *)(uVar12 + 0x10)) {
                puVar1 = *(uint **)(*(int *)(uVar12 + 0xc) + uVar13 * 4 + -4);
                if (puVar1[1] == 0) {
                  uVar7 = (-*puVar1 | *puVar1) >> 0x1f;
                }
                else {
                  uVar9 = puVar1[1];
                  uVar7 = 1;
                  local_4c[0] = 0;
                  while (cVar3 = FUN_100269d0(uVar9 + 0xc,&local_50,local_4c), cVar3 != '\0') {
                    iVar2 = FUN_10026c50(local_50);
                    uVar7 = uVar7 + iVar2;
                  }
                }
                uVar10 = uVar10 + uVar7;
              }
            }
            uVar14 = uVar14 + uVar10;
          }
        }
        uVar6 = uVar6 + uVar14;
      }
    }
    iVar4 = iVar4 + uVar6;
  }
  return iVar4;
}

