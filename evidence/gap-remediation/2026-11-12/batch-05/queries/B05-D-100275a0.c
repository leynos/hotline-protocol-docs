
undefined4 FUN_100275a0(undefined4 *param_1,undefined4 param_2)

{
  int *piVar1;
  char cVar2;
  undefined4 *puVar3;
  uint uVar4;
  uint uVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  uint uVar8;
  undefined4 *puVar9;
  uint uVar10;
  undefined4 local_40;
  undefined4 local_3c [5];
  
  cVar2 = FUN_1002cac0(*param_1);
  if (cVar2 == '\0') {
    uVar5 = 0;
    do {
      uVar5 = uVar5 + 1;
      if ((uint)param_1[4] < uVar5) {
        return 0;
      }
      piVar1 = *(int **)(param_1[3] + uVar5 * 4 + -4);
      if (*piVar1 == 0) {
        if (piVar1[1] == 0) {
          cVar2 = '\0';
        }
        else {
          puVar7 = (undefined4 *)piVar1[1];
          cVar2 = FUN_1002cac0(*puVar7,param_2);
          if (cVar2 == '\0') {
            uVar8 = 0;
            do {
              uVar8 = uVar8 + 1;
              if ((uint)puVar7[4] < uVar8) {
                cVar2 = '\0';
                goto LAB_10027894;
              }
              piVar1 = *(int **)(puVar7[3] + uVar8 * 4 + -4);
              if (*piVar1 == 0) {
                if (piVar1[1] == 0) {
                  cVar2 = '\0';
                }
                else {
                  puVar9 = (undefined4 *)piVar1[1];
                  cVar2 = FUN_1002cac0(*puVar9,param_2);
                  if (cVar2 == '\0') {
                    uVar10 = 0;
                    do {
                      uVar10 = uVar10 + 1;
                      if ((uint)puVar9[4] < uVar10) {
                        cVar2 = '\0';
                        goto LAB_1002783c;
                      }
                      piVar1 = *(int **)(puVar9[3] + uVar10 * 4 + -4);
                      if (*piVar1 == 0) {
                        if (piVar1[1] == 0) {
                          cVar2 = '\0';
                        }
                        else {
                          puVar6 = (undefined4 *)piVar1[1];
                          cVar2 = FUN_1002cac0(*puVar6,param_2);
                          if (cVar2 == '\0') {
                            uVar4 = 0;
                            do {
                              uVar4 = uVar4 + 1;
                              if ((uint)puVar6[4] < uVar4) {
                                cVar2 = '\0';
                                goto LAB_100277e4;
                              }
                              piVar1 = *(int **)(puVar6[3] + uVar4 * 4 + -4);
                              if (*piVar1 == 0) {
                                if (piVar1[1] == 0) {
                                  cVar2 = '\0';
                                }
                                else {
                                  puVar3 = (undefined4 *)piVar1[1];
                                  cVar2 = FUN_10027900(*puVar3,param_2);
                                  if (cVar2 == '\0') {
                                    local_3c[0] = 0;
                                    do {
                                      cVar2 = FUN_100269d0(puVar3 + 3,&local_40,local_3c);
                                      if (cVar2 == '\0') {
                                        cVar2 = '\0';
                                        goto LAB_1002778c;
                                      }
                                      cVar2 = FUN_10026420(local_40,param_2);
                                    } while (cVar2 == '\0');
                                    cVar2 = '\x01';
                                  }
                                  else {
                                    cVar2 = '\x01';
                                  }
                                }
                              }
                              else {
                                cVar2 = FUN_1002cac0(*piVar1,param_2);
                              }
LAB_1002778c:
                            } while (cVar2 == '\0');
                            cVar2 = '\x01';
                          }
                          else {
                            cVar2 = '\x01';
                          }
                        }
                      }
                      else {
                        cVar2 = FUN_1002cac0(*piVar1,param_2);
                      }
LAB_100277e4:
                    } while (cVar2 == '\0');
                    cVar2 = '\x01';
                  }
                  else {
                    cVar2 = '\x01';
                  }
                }
              }
              else {
                cVar2 = FUN_1002cac0(*piVar1,param_2);
              }
LAB_1002783c:
            } while (cVar2 == '\0');
            cVar2 = '\x01';
          }
          else {
            cVar2 = '\x01';
          }
        }
      }
      else {
        cVar2 = FUN_1002cac0(*piVar1,param_2);
      }
LAB_10027894:
    } while (cVar2 == '\0');
  }
  return 1;
}

