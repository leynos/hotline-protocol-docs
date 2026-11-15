
void FUN_10008fd0(int param_1,int *param_2,uint *param_3)

{
  byte bVar1;
  bool bVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  undefined4 uVar6;
  byte *pbVar7;
  byte *pbVar8;
  short local_2020;
  ushort local_201e;
  short local_201c;
  short local_201a;
  short local_2018;
  short local_2016;
  short local_2014;
  short local_2012;
  short local_2010;
  short local_200e;
  short local_200c;
  short local_200a;
  short local_2008;
  short local_2006;
  undefined2 local_1fea;
  undefined1 local_1fe8;
  undefined1 local_1fe7;
  undefined1 local_1fe6;
  undefined1 local_1fe5;
  undefined4 local_1fe4;
  undefined2 local_1fe0;
  undefined2 local_1fde;
  undefined2 local_1fdc;
  char local_1fda;
  undefined4 local_1fd8;
  byte local_1fd4 [8116];
  
  iVar3 = FUN_1002af80(0xfffffffe,0,0x100902d9,0,0);
  FUN_1002c220(iVar3,0x21);
  uVar4 = FUN_1002c3b0(iVar3,0,&local_2020,0x2000,0);
  if (iVar3 != 0) {
    FUN_1002b2f0(iVar3);
  }
  if ((0x5f < uVar4) &&
     ((pbVar7 = local_1fd4 + (uVar4 - 0x4c), local_2020 == 4 || (local_2020 == 5)))) {
    *param_3 = (uint)local_201e;
    *param_2 = (int)local_201c;
    param_2[1] = (int)local_201a;
    param_2[2] = (int)local_2018;
    param_2[3] = (int)local_2016;
    param_2[4] = (int)local_2014;
    param_2[5] = (int)local_2012;
    param_2[6] = (int)local_2010;
    param_2[7] = (int)local_200e;
    param_2[8] = (int)local_200c;
    param_2[9] = (int)local_200a;
    param_2[10] = (int)local_2008;
    param_2[0xb] = (int)local_2006;
    *(undefined2 *)(param_1 + 0xa8) = local_1fea;
    *(undefined1 *)(param_1 + 0x9c) = local_1fe8;
    *(undefined1 *)(param_1 + 0x9d) = local_1fe7;
    *(undefined1 *)(param_1 + 0x9e) = local_1fe6;
    *(undefined1 *)(param_1 + 0x9f) = local_1fe5;
    *(undefined4 *)(param_1 + 0xac) = local_1fe4;
    *(undefined2 *)(param_1 + 0xa0) = local_1fe0;
    *(undefined2 *)(param_1 + 0xa4) = local_1fde;
    *(undefined2 *)(param_1 + 0xa6) = local_1fdc;
    if (local_1fda != '\0') {
      DAT_10093be9 = 1;
    }
    *(undefined4 *)(param_1 + 0x454) = local_1fd8;
    bVar2 = false;
    if ((local_1fd4 < pbVar7) && (local_1fd4 + local_1fd4[0] + 1 <= pbVar7)) {
      bVar2 = true;
    }
    if (bVar2) {
      pbVar8 = local_1fd4 + local_1fd4[0] + 1;
      bVar2 = false;
      if ((pbVar8 < pbVar7) && (pbVar8 + *pbVar8 + 1 <= pbVar7)) {
        bVar2 = true;
      }
      if (bVar2) {
        pbVar8 = pbVar8 + *pbVar8 + 1;
        bVar2 = false;
        if ((pbVar8 < pbVar7) && (pbVar8 + *pbVar8 + 1 <= pbVar7)) {
          bVar2 = true;
        }
        if (bVar2) {
          pbVar8 = pbVar8 + *pbVar8 + 1;
          if ((pbVar8 < pbVar7) && (pbVar8 + *pbVar8 + 1 <= pbVar7)) {
            bVar1 = *pbVar8;
            FUN_1007c270(param_1 + 0xcc,pbVar8,0x1f);
            bVar2 = true;
            pbVar8 = pbVar8 + bVar1 + 1;
          }
          else {
            bVar2 = false;
          }
          if (bVar2) {
            bVar2 = false;
            if ((pbVar8 < pbVar7) && (pbVar8 + *pbVar8 + 1 <= pbVar7)) {
              bVar2 = true;
            }
            if (bVar2) {
              pbVar8 = pbVar8 + *pbVar8 + 1;
              if ((pbVar8 < pbVar7) && (pbVar8 + *pbVar8 + 1 <= pbVar7)) {
                bVar1 = *pbVar8;
                FUN_1007c270(param_1 + 0xec,pbVar8,0x7f);
                bVar2 = true;
                pbVar8 = pbVar8 + bVar1 + 1;
              }
              else {
                bVar2 = false;
              }
              if (bVar2) {
                if ((pbVar8 < pbVar7) && (pbVar8 + *pbVar8 + 1 <= pbVar7)) {
                  bVar1 = *pbVar8;
                  FUN_1007c270(param_1 + 0x16c,pbVar8,0x1f);
                  bVar2 = true;
                  pbVar8 = pbVar8 + bVar1 + 1;
                }
                else {
                  bVar2 = false;
                }
                if (bVar2) {
                  if ((pbVar8 < pbVar7) && (pbVar8 + *pbVar8 + 1 <= pbVar7)) {
                    bVar1 = *pbVar8;
                    FUN_1007c270(param_1 + 0x18c,pbVar8,0x7f);
                    bVar2 = true;
                    pbVar8 = pbVar8 + bVar1 + 1;
                  }
                  else {
                    bVar2 = false;
                  }
                  if (bVar2) {
                    if ((pbVar8 < pbVar7) && (pbVar8 + *pbVar8 + 1 <= pbVar7)) {
                      bVar1 = *pbVar8;
                      FUN_1007c270(param_1 + 0x20c,pbVar8,0xff);
                      bVar2 = true;
                      pbVar8 = pbVar8 + bVar1 + 1;
                    }
                    else {
                      bVar2 = false;
                    }
                    if (bVar2) {
                      if ((pbVar8 < pbVar7) && (pbVar8 + *pbVar8 + 1 <= pbVar7)) {
                        bVar1 = *pbVar8;
                        FUN_1007c270(param_1 + 0x30c,pbVar8,0xff);
                        bVar2 = true;
                        pbVar8 = pbVar8 + bVar1 + 1;
                      }
                      else {
                        bVar2 = false;
                      }
                      if (bVar2) {
                        if (local_2020 == 4) {
                          for (iVar3 = 0; iVar3 != 5; iVar3 = iVar3 + 1) {
                            bVar2 = false;
                            if ((pbVar8 < pbVar7) && (pbVar8 + *pbVar8 + 1 <= pbVar7)) {
                              bVar2 = true;
                            }
                            if (!bVar2) goto LAB_1000975c;
                            iVar5 = FUN_100539c0(param_1 + iVar3 * 0x144 + 0x45c,pbVar8,*pbVar8 + 1)
                            ;
                            pbVar8 = pbVar8 + iVar5;
                            *(undefined1 *)(param_1 + iVar3 * 0x144 + 0x55c) = 0;
                            if ((pbVar8 < pbVar7) && (pbVar8 + *pbVar8 + 1 <= pbVar7)) {
                              bVar1 = *pbVar8;
                              FUN_1007c270(param_1 + iVar3 * 0x144 + 0x57c,pbVar8,0x1f);
                              bVar2 = true;
                              pbVar8 = pbVar8 + bVar1 + 1;
                            }
                            else {
                              bVar2 = false;
                            }
                            if (!bVar2) goto LAB_1000975c;
                          }
                        }
                        else {
                          for (iVar3 = 0; iVar3 != 5; iVar3 = iVar3 + 1) {
                            bVar2 = false;
                            if ((pbVar8 < pbVar7) && (pbVar8 + *pbVar8 + 1 <= pbVar7)) {
                              bVar2 = true;
                            }
                            if (!bVar2) goto LAB_1000975c;
                            iVar5 = FUN_100539c0(param_1 + iVar3 * 0x144 + 0x45c,pbVar8,*pbVar8 + 1)
                            ;
                            pbVar8 = pbVar8 + iVar5;
                            if ((pbVar8 < pbVar7) && (pbVar8 + *pbVar8 + 1 <= pbVar7)) {
                              bVar1 = *pbVar8;
                              FUN_1007c270(param_1 + iVar3 * 0x144 + 0x55c,pbVar8,0x1f);
                              bVar2 = true;
                              pbVar8 = pbVar8 + bVar1 + 1;
                            }
                            else {
                              bVar2 = false;
                            }
                            if (!bVar2) goto LAB_1000975c;
                            if ((pbVar8 < pbVar7) && (pbVar8 + *pbVar8 + 1 <= pbVar7)) {
                              bVar1 = *pbVar8;
                              FUN_1007c270(param_1 + iVar3 * 0x144 + 0x57c,pbVar8,0x1f);
                              bVar2 = true;
                              pbVar8 = pbVar8 + bVar1 + 1;
                            }
                            else {
                              bVar2 = false;
                            }
                            if (!bVar2) goto LAB_1000975c;
                          }
                        }
                        for (iVar3 = 0; iVar3 != 5; iVar3 = iVar3 + 1) {
                          *(undefined2 *)(param_1 + iVar3 * 0x144 + 0x458) = 0x2a;
                          iVar5 = FUN_1006ced0(0x3a,param_1 + iVar3 * 0x144 + 0x45d,
                                               *(undefined1 *)(param_1 + iVar3 * 0x144 + 0x45c));
                          *(ushort *)(param_1 + iVar3 * 0x144 + 0x45a) =
                               ~((short)((ushort)((uint)-iVar5 >> 0x10) |
                                        (ushort)((uint)iVar5 >> 0x10)) >> 0xf) & 0x157b;
                        }
                        if ((*(byte *)(param_1 + 200) >> 6 & 1) == 0) {
                          FUN_1006ea80(*(uint *)(param_1 + 0xac) >> 4 & 1);
                        }
                        goto LAB_1000986c;
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
LAB_1000975c:
  *(undefined4 *)(param_1 + 0x9c) = 0;
  *(undefined2 *)(param_1 + 0xa0) = 0x157c;
  *(undefined2 *)(param_1 + 0xa4) = 100;
  *(undefined2 *)(param_1 + 0xa6) = 10;
  *(undefined2 *)(param_1 + 0xa8) = 5;
  *(undefined4 *)(param_1 + 0xac) = 0x30;
  *(undefined4 *)(param_1 + 0x454) = 0;
  *(undefined1 *)(param_1 + 0x16c) = 0;
  *(undefined1 *)(param_1 + 0xec) = 0;
  *(undefined1 *)(param_1 + 0xcc) = 0;
  *(undefined1 *)(param_1 + 0x30c) = 0;
  *(undefined1 *)(param_1 + 0x20c) = 0;
  *(undefined1 *)(param_1 + 0x18c) = 0;
  for (iVar3 = 0; iVar3 != 5; iVar3 = iVar3 + 1) {
    *(undefined2 *)(param_1 + iVar3 * 0x144 + 0x458) = 0x2a;
    *(undefined2 *)(param_1 + iVar3 * 0x144 + 0x45a) = 0x157b;
    *(undefined1 *)(param_1 + iVar3 * 0x144 + 0x45c) = 0;
    *(undefined1 *)(param_1 + iVar3 * 0x144 + 0x55c) = 0;
    *(undefined1 *)(param_1 + iVar3 * 0x144 + 0x57c) = 0;
  }
  if (param_2 != (int *)0x0) {
    param_2[2] = 0;
    param_2[3] = 0;
    *param_2 = 0;
    param_2[1] = 0;
    param_2[6] = 0;
    param_2[7] = 0;
    param_2[4] = 0;
    param_2[5] = 0;
    param_2[10] = 0;
    param_2[0xb] = 0;
    param_2[8] = 0;
    param_2[9] = 0;
  }
  if (param_3 != (uint *)0x0) {
    *param_3 = 7;
  }
LAB_1000986c:
  if (*(int *)(param_1 + 0x454) == 0) {
    uVar6 = FUN_1006e310(0x80000000,0x7fffffff);
    *(undefined4 *)(param_1 + 0x454) = uVar6;
  }
  if (*(char *)(param_1 + 0x45c) == '\0') {
    FUN_1007c240(param_1 + 0x45c,PTR_DAT_1008ee1c);
    *(undefined1 *)(param_1 + 0x55c) = 0;
    *(undefined1 *)(param_1 + 0x57c) = 0;
  }
  if (*(short *)(param_1 + 0xa0) == 0) {
    *(undefined2 *)(param_1 + 0xa0) = 0x157c;
  }
  if (*(short *)(param_1 + 0xa4) == 0) {
    *(undefined2 *)(param_1 + 0xa4) = 100;
  }
  if (*(short *)(param_1 + 0xa6) == 0) {
    *(undefined2 *)(param_1 + 0xa6) = 10;
  }
  if (*(char *)(param_1 + 0x16c) == '\0') {
    FUN_1007c240(param_1 + 0x16c,0x100902df);
  }
  return;
}

