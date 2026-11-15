
int FUN_10027130(int *param_1)

{
  int *piVar1;
  int iVar2;
  char cVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  int iVar13;
  uint uVar14;
  int *local_44;
  undefined4 local_40 [5];
  
  if (param_1[1] == 0) {
    if (*param_1 == 0) {
      iVar4 = 0;
    }
    else {
      iVar4 = FUN_1002c4d0(*param_1,0);
    }
  }
  else {
    iVar5 = param_1[1];
    iVar4 = 0;
    uVar6 = 0;
    while (uVar6 = uVar6 + 1, uVar6 <= *(uint *)(iVar5 + 0x10)) {
      piVar1 = *(int **)(*(int *)(iVar5 + 0xc) + uVar6 * 4 + -4);
      if (piVar1[1] == 0) {
        if (*piVar1 == 0) {
          iVar7 = 0;
        }
        else {
          iVar7 = FUN_1002c4d0(*piVar1,0);
        }
      }
      else {
        iVar8 = piVar1[1];
        iVar7 = 0;
        uVar9 = 0;
        while (uVar9 = uVar9 + 1, uVar9 <= *(uint *)(iVar8 + 0x10)) {
          piVar1 = *(int **)(*(int *)(iVar8 + 0xc) + uVar9 * 4 + -4);
          if (piVar1[1] == 0) {
            if (*piVar1 == 0) {
              iVar10 = 0;
            }
            else {
              iVar10 = FUN_1002c4d0(*piVar1,0);
            }
          }
          else {
            iVar12 = piVar1[1];
            iVar10 = 0;
            uVar14 = 0;
            while (uVar14 = uVar14 + 1, uVar14 <= *(uint *)(iVar12 + 0x10)) {
              piVar1 = *(int **)(*(int *)(iVar12 + 0xc) + uVar14 * 4 + -4);
              if (piVar1[1] == 0) {
                if (*piVar1 == 0) {
                  iVar11 = 0;
                }
                else {
                  iVar11 = FUN_1002c4d0(*piVar1,0);
                }
              }
              else {
                iVar13 = piVar1[1];
                iVar11 = 0;
                local_40[0] = 0;
                while (cVar3 = FUN_10026e50(iVar13 + 0xc,&local_44,local_40), cVar3 != '\0') {
                  if (local_44[1] == 0) {
                    if (*local_44 == 0) {
                      iVar2 = 0;
                    }
                    else {
                      iVar2 = FUN_10001470(*local_44,0);
                    }
                  }
                  else {
                    iVar2 = FUN_10026ea0(local_44[1]);
                  }
                  iVar11 = iVar11 + iVar2;
                }
              }
              iVar10 = iVar10 + iVar11;
            }
          }
          iVar7 = iVar7 + iVar10;
        }
      }
      iVar4 = iVar4 + iVar7;
    }
  }
  return iVar4;
}

