
int * FUN_10026670(int *param_1,short param_2)

{
  int *piVar1;
  int *piVar2;
  int *piVar3;
  char cVar4;
  int *piVar5;
  uint uVar6;
  int *piVar7;
  uint uVar8;
  int *piVar9;
  uint uVar10;
  undefined4 local_44;
  undefined4 local_40 [5];
  
  if (param_1 != (int *)0x0) {
    uVar6 = 0;
    while (uVar6 = uVar6 + 1, uVar6 <= (uint)param_1[4]) {
      piVar3 = *(int **)(param_1[3] + uVar6 * 4 + -4);
      if (piVar3 != (int *)0x0) {
        if (*piVar3 == 0) {
          if ((piVar3[1] != 0) && (piVar7 = (int *)piVar3[1], piVar7 != (int *)0x0)) {
            uVar8 = 0;
            while (uVar8 = uVar8 + 1, uVar8 <= (uint)piVar7[4]) {
              piVar2 = *(int **)(piVar7[3] + uVar8 * 4 + -4);
              if (piVar2 != (int *)0x0) {
                if (*piVar2 == 0) {
                  if ((piVar2[1] != 0) && (piVar9 = (int *)piVar2[1], piVar9 != (int *)0x0)) {
                    uVar10 = 0;
                    while (uVar10 = uVar10 + 1, uVar10 <= (uint)piVar9[4]) {
                      piVar1 = *(int **)(piVar9[3] + uVar10 * 4 + -4);
                      if (piVar1 != (int *)0x0) {
                        if (*piVar1 == 0) {
                          if ((piVar1[1] != 0) && (piVar5 = (int *)piVar1[1], piVar5 != (int *)0x0))
                          {
                            local_40[0] = 0;
                            while (cVar4 = FUN_100269d0(piVar5 + 3,&local_44,local_40),
                                  cVar4 != '\0') {
                              FUN_10026250(local_44,1);
                            }
                            FUN_10055880(piVar5 + 3);
                            if (*piVar5 != 0) {
                              FUN_100269a0(*piVar5);
                            }
                            FUN_10026610(piVar5 + 3,0xffffffff);
                            FUN_1006d290(piVar5);
                          }
                        }
                        else {
                          FUN_1002b2f0(*piVar1);
                        }
                        FUN_1006d290(piVar1);
                      }
                    }
                    FUN_10055880(piVar9 + 3);
                    if (*piVar9 != 0) {
                      FUN_1002b2f0(*piVar9);
                    }
                    if (piVar9 != (int *)0xfffffff4) {
                      FUN_10055480(piVar9 + 3,0);
                    }
                    FUN_1006d290(piVar9);
                  }
                }
                else {
                  FUN_1002b2f0(*piVar2);
                }
                FUN_1006d290(piVar2);
              }
            }
            FUN_10055880(piVar7 + 3);
            if (*piVar7 != 0) {
              FUN_1002b2f0(*piVar7);
            }
            if (piVar7 != (int *)0xfffffff4) {
              FUN_10055480(piVar7 + 3,0);
            }
            FUN_1006d290(piVar7);
          }
        }
        else {
          FUN_1002b2f0(*piVar3);
        }
        FUN_1006d290(piVar3);
      }
    }
    FUN_10055880(param_1 + 3);
    if (*param_1 != 0) {
      FUN_1002b2f0(*param_1);
    }
    if (param_1 != (int *)0xfffffff4) {
      FUN_10055480(param_1 + 3,0);
    }
    if (0 < param_2) {
      FUN_1006d290(param_1);
    }
  }
  return param_1;
}

