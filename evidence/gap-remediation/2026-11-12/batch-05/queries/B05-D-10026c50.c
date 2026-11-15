
uint FUN_10026c50(uint *param_1)

{
  uint *puVar1;
  uint uVar2;
  char cVar3;
  uint uVar4;
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
  uint *local_44;
  undefined4 local_40 [5];
  
  if (param_1[1] == 0) {
    uVar4 = (-*param_1 | *param_1) >> 0x1f;
  }
  else {
    uVar5 = param_1[1];
    uVar4 = 1;
    uVar6 = 0;
    while (uVar6 = uVar6 + 1, uVar6 <= *(uint *)(uVar5 + 0x10)) {
      puVar1 = *(uint **)(*(int *)(uVar5 + 0xc) + uVar6 * 4 + -4);
      if (puVar1[1] == 0) {
        uVar7 = (-*puVar1 | *puVar1) >> 0x1f;
      }
      else {
        uVar8 = puVar1[1];
        uVar7 = 1;
        uVar9 = 0;
        while (uVar9 = uVar9 + 1, uVar9 <= *(uint *)(uVar8 + 0x10)) {
          puVar1 = *(uint **)(*(int *)(uVar8 + 0xc) + uVar9 * 4 + -4);
          if (puVar1[1] == 0) {
            uVar11 = (-*puVar1 | *puVar1) >> 0x1f;
          }
          else {
            uVar13 = puVar1[1];
            uVar11 = 1;
            uVar14 = 0;
            while (uVar14 = uVar14 + 1, uVar14 <= *(uint *)(uVar13 + 0x10)) {
              puVar1 = *(uint **)(*(int *)(uVar13 + 0xc) + uVar14 * 4 + -4);
              if (puVar1[1] == 0) {
                uVar10 = (-*puVar1 | *puVar1) >> 0x1f;
              }
              else {
                uVar12 = puVar1[1];
                uVar10 = 1;
                local_40[0] = 0;
                while (cVar3 = FUN_10026e50(uVar12 + 0xc,&local_44,local_40), cVar3 != '\0') {
                  if (local_44[1] == 0) {
                    uVar2 = (-*local_44 | *local_44) >> 0x1f;
                  }
                  else {
                    uVar2 = FUN_10026a20(local_44[1]);
                  }
                  uVar10 = uVar10 + uVar2;
                }
              }
              uVar11 = uVar11 + uVar10;
            }
          }
          uVar7 = uVar7 + uVar11;
        }
      }
      uVar4 = uVar4 + uVar7;
    }
  }
  return uVar4;
}

