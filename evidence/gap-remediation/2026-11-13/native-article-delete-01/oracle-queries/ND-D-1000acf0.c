
void FUN_1000acf0(int param_1)

{
  undefined *puVar1;
  int iVar2;
  int iVar3;
  short sVar5;
  char cVar7;
  undefined1 *puVar4;
  undefined1 uVar8;
  ushort uVar6;
  uint uVar9;
  int iVar10;
  undefined4 uVar11;
  undefined4 *puVar12;
  undefined4 *puVar13;
  short local_50 [2];
  undefined4 local_4c;
  undefined4 local_48;
  int local_44;
  int local_40;
  undefined1 auStack_3c [4];
  undefined4 local_38;
  
  puVar1 = PTR_PTR_10088d98;
  local_4c = FUN_10056380(0,0);
  iVar2 = FUN_10057d00();
LAB_1000ad2c:
  iVar10 = 0;
  local_48 = 0xc;
  if (*(int *)(param_1 + 0x18) != 0) {
    iVar10 = FUN_10058510(*(undefined4 *)(param_1 + 0x18),auStack_3c,&local_48);
  }
  if (iVar10 == 0) {
    if (*(int *)(param_1 + 0x1c) != 0) {
      iVar10 = FUN_10058510(*(undefined4 *)(param_1 + 0x1c),auStack_3c,&local_48);
    }
    if (iVar10 == 0) goto LAB_1000adf0;
  }
  if (*(char *)(param_1 + 200) < '\0') {
    FUN_10058160(iVar10);
  }
  else {
    FUN_100582b0(iVar10,puVar1,param_1);
    iVar3 = FUN_10052b70(0xc);
    *(int *)(iVar3 + 4) = iVar10;
    *(undefined4 *)(iVar3 + 8) = local_38;
    FUN_10055a80(param_1 + 0x30,iVar3);
  }
  goto LAB_1000ad2c;
LAB_1000adf0:
  puVar13 = *(undefined4 **)(param_1 + 0x30);
LAB_1000b2bc:
  do {
    if (puVar13 == (undefined4 *)0x0) {
      puVar13 = *(undefined4 **)(param_1 + 0x34);
      do {
        while( true ) {
          if (puVar13 == (undefined4 *)0x0) {
            if ((*(char *)(param_1 + 200) < '\0') && (*(int *)(param_1 + 0x34) == 0)) {
              FUN_10082630(param_1);
            }
            FUN_100563d0(local_4c);
            return;
          }
          cVar7 = FUN_10058360(puVar13[1]);
          if (cVar7 != '\0') break;
          FUN_100068e0(param_1,puVar13,s_Connection_closed_100903a6);
          puVar12 = (undefined4 *)*puVar13;
          FUN_10004930(param_1,puVar13);
          puVar13 = puVar12;
        }
        cVar7 = FUN_10058450(puVar13[1]);
        if (cVar7 == '\0') {
          if (puVar13[0x26] == 0) {
            while (iVar10 = FUN_10058880(puVar13[1],0,1), iVar10 != 0) {
              if (0x3c < (uint)(iVar2 - puVar13[0x2b])) {
                puVar13[0x2b] = iVar2;
                *(undefined2 *)(puVar13 + 0x52) = 0;
              }
              local_40 = iVar10;
              if (0x78 < *(ushort *)(puVar13 + 0x52)) {
                FUN_100583b0(puVar13[1]);
                uVar11 = puVar13[4];
                if ((int)((*(uint *)(param_1 + 0x440) | 0xffffffdf) -
                         (*(uint *)(param_1 + 0x440) - 0x20 >> 1)) < 0) {
                  puVar4 = (undefined1 *)FUN_10055770(param_1 + 0x43c,1);
                }
                else {
                  puVar4 = (undefined1 *)FUN_1006d260(0x74);
                  if (puVar4 != (undefined1 *)0x0) {
                    *(undefined4 *)(puVar4 + 0xc) = 0;
                    *(undefined4 *)(puVar4 + 8) = 0;
                    *(undefined4 *)(puVar4 + 4) = 0xffffffff;
                    *puVar4 = 1;
                    puVar4[0x10] = 0;
                    puVar4[0x31] = 0;
                  }
                }
                if (puVar4 != (undefined1 *)0x0) {
                  *puVar4 = 1;
                  *(undefined4 *)(puVar4 + 8) = uVar11;
                  *(undefined4 *)(puVar4 + 0xc) = uVar11;
                  uVar8 = FUN_10057e30(puVar4 + 0x11,0x20,0x21);
                  puVar4[0x10] = uVar8;
                  iVar10 = FUN_10057d00();
                  *(int *)(puVar4 + 4) = iVar10 + 0x708;
                  puVar4[0x31] = 0;
                  FUN_100554e0(param_1 + 0x43c,puVar4);
                }
                FUN_100068e0(param_1,puVar13,s_Autobanned_for_flooding_1009033e);
                if (local_40 != 0) {
                  FUN_100589b0(local_40);
                }
                goto LAB_1000bc4c;
              }
              *(short *)(puVar13 + 0x52) = *(short *)(puVar13 + 0x52) + 1;
              FUN_10005400(param_1,puVar13,0);
              puVar13[0x27] = iVar2;
              FUN_10058c00(iVar10,local_4c);
              uVar6 = FUN_10058ba0(iVar10);
              if (*(char *)((int)puVar13 + 0x14a) < '\0') {
                if (uVar6 == 0xd4) {
                  FUN_10012f40(param_1,puVar13,iVar10,local_4c);
                }
                else if (uVar6 < 0xd4) {
                  if (uVar6 == 0x74) {
                    FUN_10018620(param_1,puVar13,iVar10,local_4c);
                  }
                  else if (uVar6 < 0x74) {
                    if (uVar6 == 0x6c) {
                      FUN_1000f4e0(param_1,puVar13,iVar10,local_4c);
                    }
                    else if (uVar6 < 0x6c) {
                      if (uVar6 == 0x67) {
                        FUN_1000f260(param_1,puVar13,iVar10,local_4c);
                      }
                      else if (uVar6 < 0x67) {
                        if (uVar6 != 0x65) goto LAB_1000bc18;
                        FUN_1000f130(param_1,puVar13,iVar10,local_4c);
                      }
                      else {
                        if (uVar6 != 0x69) goto LAB_1000bc18;
                        FUN_1000fc20(param_1,puVar13,iVar10,local_4c);
                      }
                    }
                    else if (uVar6 == 0x70) {
                      FUN_10017f30(param_1,puVar13,iVar10,local_4c);
                    }
                    else if (uVar6 < 0x70) {
                      if (uVar6 != 0x6e) goto LAB_1000bc18;
                      FUN_10015e70(param_1,puVar13,iVar10,local_4c);
                    }
                    else if (uVar6 == 0x72) {
                      FUN_10018340(param_1,puVar13,iVar10,local_4c);
                    }
                    else if (uVar6 < 0x72) {
                      FUN_100188e0(param_1,puVar13,iVar10,local_4c);
                    }
                    else {
                      FUN_100183c0(param_1,puVar13,iVar10,local_4c);
                    }
                  }
                  else if (uVar6 == 0xcc) {
                    FUN_100140e0(param_1,puVar13,iVar10,local_4c);
                  }
                  else if (uVar6 < 0xcc) {
                    if (uVar6 == 200) {
                      FUN_100100a0(param_1,puVar13,iVar10,local_4c);
                    }
                    else if (uVar6 < 200) {
                      if (uVar6 != 0x78) goto LAB_1000bc18;
                      FUN_10018760(param_1,puVar13,iVar10,local_4c);
                    }
                    else if (uVar6 == 0xca) {
                      FUN_100121a0(param_1,puVar13,iVar10,local_4c);
                    }
                    else {
                      if (uVar6 < 0xca) goto LAB_1000bc18;
                      FUN_100130f0(param_1,puVar13,iVar10,local_4c);
                    }
                  }
                  else if (uVar6 == 0xd0) {
                    FUN_100177d0(param_1,puVar13,iVar10,local_4c);
                  }
                  else if (uVar6 < 0xd0) {
                    if (uVar6 == 0xce) {
                      FUN_10016ba0(param_1,puVar13,iVar10,local_4c);
                    }
                    else if (uVar6 < 0xce) {
                      FUN_100143f0(param_1,puVar13,iVar10,local_4c);
                    }
                    else {
                      FUN_100170c0(param_1,puVar13,iVar10,local_4c);
                    }
                  }
                  else if (uVar6 == 0xd2) {
                    FUN_10012850(param_1,puVar13,iVar10,local_4c);
                  }
                  else {
                    if (0xd1 < uVar6) goto LAB_1000bc18;
                    FUN_10017c10(param_1,puVar13,iVar10,local_4c);
                  }
                }
                else if (uVar6 == 0x163) {
                  FUN_1000f990(param_1,puVar13,iVar10,local_4c);
                }
                else if (uVar6 < 0x163) {
                  if (uVar6 == 0x15c) {
                    FUN_10015160(param_1,puVar13,iVar10,local_4c);
                  }
                  else if (uVar6 < 0x15c) {
                    if (uVar6 == 300) {
                      FUN_10011870(param_1,puVar13,iVar10,local_4c);
                    }
                    else if (uVar6 < 300) {
                      if (uVar6 == 0xd6) {
                        FUN_10013040(param_1,puVar13,iVar10,local_4c);
                      }
                      else {
                        if (0xd5 < uVar6) goto LAB_1000bc18;
                        FUN_10013930(param_1,puVar13,iVar10,local_4c);
                      }
                    }
                    else if (uVar6 == 0x130) {
                      FUN_10016ad0(param_1,puVar13,iVar10,local_4c);
                    }
                    else {
                      if ((0x12f < uVar6) || (uVar6 < 0x12f)) goto LAB_1000bc18;
                      FUN_10016150(param_1,puVar13,iVar10,local_4c);
                    }
                  }
                  else if (uVar6 == 0x160) {
                    FUN_10014bc0(param_1,puVar13,iVar10,local_4c);
                  }
                  else if (uVar6 < 0x160) {
                    if (uVar6 == 0x15e) {
                      FUN_100146f0(param_1,puVar13,iVar10,local_4c);
                    }
                    else if (uVar6 < 0x15e) {
                      FUN_10015500(param_1,puVar13,iVar10,local_4c);
                    }
                    else {
                      FUN_100149e0(param_1,puVar13,iVar10,local_4c);
                    }
                  }
                  else {
                    if (0x161 < uVar6) goto LAB_1000bc18;
                    FUN_10014df0(param_1,puVar13,iVar10,local_4c);
                  }
                }
                else if (uVar6 == 400) {
                  FUN_10011580(param_1,puVar13,iVar10,local_4c);
                }
                else if (uVar6 < 400) {
                  if (uVar6 == 0x17c) {
                    FUN_10010b70(param_1,puVar13,iVar10,local_4c);
                  }
                  else if (uVar6 < 0x17c) {
                    if (uVar6 == 0x173) {
                      FUN_10011370(param_1,puVar13,iVar10,local_4c);
                    }
                    else {
                      if ((0x172 < uVar6) || (uVar6 < 0x172)) goto LAB_1000bc18;
                      FUN_100102c0(param_1,puVar13,iVar10,local_4c);
                    }
                  }
                  else if (uVar6 == 0x17e) {
                    FUN_10011110(param_1,puVar13,iVar10,local_4c);
                  }
                  else {
                    if (0x17d < uVar6) goto LAB_1000bc18;
                    FUN_10010ee0(param_1,puVar13,iVar10,local_4c);
                  }
                }
                else if (uVar6 == 0x19b) {
                  FUN_100108a0(param_1,puVar13,iVar10,local_4c);
                }
                else if (uVar6 < 0x19b) {
                  if (uVar6 < 0x19a) goto LAB_1000bc18;
                  FUN_10010470(param_1,puVar13,iVar10,local_4c);
                }
                else if (uVar6 == 500) {
                  FUN_10018c00(param_1,puVar13,iVar10,local_4c);
                }
                else {
LAB_1000bc18:
                  FUN_10014640(param_1,puVar13,iVar10,local_4c);
                }
              }
              else if (uVar6 == 0x79) {
                FUN_10011ee0(param_1,puVar13,iVar10,local_4c);
              }
              else {
                if ((0x78 < uVar6) || (uVar6 != 0x6b)) {
                  FUN_100583b0(puVar13[1]);
                  if (local_40 != 0) {
                    FUN_100589b0(local_40);
                  }
                  goto LAB_1000bc4c;
                }
                FUN_10011960(param_1,puVar13,iVar10,local_4c);
              }
              if (local_40 != 0) {
                FUN_100589b0(local_40);
              }
            }
            if ((*(char *)((int)puVar13 + 0x14a) < '\0') || ((uint)(iVar2 - puVar13[0x27]) < 0x3d))
            {
              if (600 < (uint)(iVar2 - puVar13[0x27])) {
                FUN_10005400(param_1,puVar13,1);
              }
            }
            else {
              FUN_100583b0(puVar13[1]);
            }
          }
          else if (0x1e < (uint)(iVar2 - puVar13[0x26])) {
            FUN_100583b0(puVar13[1]);
          }
        }
LAB_1000bc4c:
        puVar13 = (undefined4 *)*puVar13;
      } while( true );
    }
    cVar7 = FUN_10058360(puVar13[1]);
    if (cVar7 == '\0') {
      puVar12 = (undefined4 *)*puVar13;
      FUN_10058160(puVar13[1]);
      FUN_10055b20(param_1 + 0x30,puVar13);
      FUN_10052c10(puVar13);
      puVar13 = puVar12;
      goto LAB_1000b2bc;
    }
    cVar7 = FUN_10058450(puVar13[1]);
    if ((cVar7 == '\0') && (sVar5 = FUN_10058650(puVar13[1],&local_44,local_50), sVar5 != 0)) {
      if (sVar5 == 1) {
        if ((local_44 != 0x484f544c) || ((local_50[0] != 2 && (local_50[0] != 3)))) {
          FUN_100587f0(puVar13[1],1);
          FUN_10058400(puVar13[1]);
          uVar11 = FUN_10058270(puVar13[1]);
          FUN_100069b0(param_1,uVar11,s_Incompatible_version___4_4s_hu__1009036d,&local_44,
                       local_50[0]);
          FUN_10057940(0,0x82,1);
          goto LAB_1000b2b8;
        }
        FUN_10058770(puVar13[1]);
        if (local_50[0] == 2) {
          if (*(short *)(param_1 + 0xa8) != 0) {
            uVar9 = 0;
            for (puVar12 = *(undefined4 **)(param_1 + 0x34); puVar12 != (undefined4 *)0x0;
                puVar12 = (undefined4 *)*puVar12) {
              if (puVar12[4] == puVar13[2]) {
                uVar9 = uVar9 + 1;
              }
            }
            if (*(ushort *)(param_1 + 0xa8) <= uVar9) {
              FUN_10058160(puVar13[1]);
              goto LAB_1000b1d4;
            }
          }
          if (*(int *)(param_1 + 0x410) == puVar13[2]) {
            uVar9 = *(int *)(param_1 + 0x418) + 1;
            *(uint *)(param_1 + 0x418) = uVar9;
            if ((10 < uVar9) && ((uint)(iVar2 - *(int *)(param_1 + 0x414)) < 0x1e)) {
              uVar11 = *(undefined4 *)(param_1 + 0x410);
              if ((int)((*(uint *)(param_1 + 0x440) | 0xffffffdf) -
                       (*(uint *)(param_1 + 0x440) - 0x20 >> 1)) < 0) {
                puVar4 = (undefined1 *)FUN_10055770(param_1 + 0x43c,1);
              }
              else {
                puVar4 = (undefined1 *)FUN_1006d260(0x74);
                if (puVar4 != (undefined1 *)0x0) {
                  *(undefined4 *)(puVar4 + 0xc) = 0;
                  *(undefined4 *)(puVar4 + 8) = 0;
                  *(undefined4 *)(puVar4 + 4) = 0xffffffff;
                  *puVar4 = 1;
                  puVar4[0x10] = 0;
                  puVar4[0x31] = 0;
                }
              }
              if (puVar4 != (undefined1 *)0x0) {
                *puVar4 = 1;
                *(undefined4 *)(puVar4 + 8) = uVar11;
                *(undefined4 *)(puVar4 + 0xc) = uVar11;
                uVar8 = FUN_10057e30(puVar4 + 0x11,0x20,0x21);
                puVar4[0x10] = uVar8;
                iVar10 = FUN_10057d00();
                *(int *)(puVar4 + 4) = iVar10 + 0x708;
                puVar4[0x31] = 0;
                FUN_100554e0(param_1 + 0x43c,puVar4);
              }
              uVar11 = FUN_10058270(puVar13[1]);
              FUN_100069b0(param_1,uVar11,s_Autobanned_for_flooding_1009033e);
              FUN_10058160(puVar13[1]);
              goto LAB_1000b1d4;
            }
          }
          else {
            *(undefined4 *)(param_1 + 0x410) = puVar13[2];
            *(int *)(param_1 + 0x414) = iVar2;
            *(undefined4 *)(param_1 + 0x418) = 0;
          }
          iVar10 = FUN_10052b70(0x14c);
          *(undefined4 *)(iVar10 + 4) = puVar13[1];
          *(int *)(iVar10 + 0xa0) = iVar2;
          *(int *)(iVar10 + 0x9c) = iVar2;
          sVar5 = *(short *)(param_1 + 0x40c);
          *(short *)(param_1 + 0x40c) = sVar5 + 1;
          if (sVar5 == -1) {
            sVar5 = *(short *)(param_1 + 0x40c) + 1;
            *(short *)(param_1 + 0x40c) = sVar5;
          }
          else {
            sVar5 = *(short *)(param_1 + 0x40c);
          }
          *(short *)(iVar10 + 0x14) = sVar5;
          *(undefined4 *)(iVar10 + 0x10) = puVar13[2];
          FUN_10055a80(param_1 + 0x34,iVar10);
          *(int *)(param_1 + 0x428) = *(int *)(param_1 + 0x428) + 1;
          *(int *)(param_1 + 0x430) = *(int *)(param_1 + 0x430) + 1;
          FUN_10057940(0,0x80,1);
          FUN_100068e0(param_1,iVar10,s_Connection_established_10090356);
          if (*(uint *)(param_1 + 0x42c) < *(uint *)(param_1 + 0x428)) {
            *(undefined4 *)(param_1 + 0x42c) = *(undefined4 *)(param_1 + 0x428);
          }
          if (*(int *)(param_1 + 0x8c) != 0) {
            FUN_10021940(*(undefined4 *)(param_1 + 0x8c),*(undefined4 *)(param_1 + 0x428),
                         *(int *)(param_1 + 0x3c) + *(int *)(param_1 + 0x48),
                         *(int *)(param_1 + 0x6c) + *(int *)(param_1 + 0x78),
                         *(undefined4 *)(param_1 + 0x54),*(undefined4 *)(param_1 + 0x42c),
                         *(undefined4 *)(param_1 + 0x430),*(undefined4 *)(param_1 + 0x434));
          }
          *(undefined2 *)(param_1 + 0xbe) = 0;
          *(undefined2 *)(param_1 + 0xbc) = 0;
        }
        else if (local_50[0] == 3) {
          uVar11 = FUN_10058270(puVar13[1]);
          FUN_10058220(puVar13[1],0);
          FUN_10058160(puVar13[1]);
          FUN_1006d440(uVar11,puVar1,param_1);
          FUN_100554e0(param_1 + 0x80,uVar11);
        }
LAB_1000b1d4:
        puVar12 = (undefined4 *)*puVar13;
        FUN_10055b20(param_1 + 0x30,puVar13);
        FUN_10052c10(puVar13);
        puVar13 = puVar12;
      }
      else {
        uVar11 = FUN_10058270(puVar13[1]);
        FUN_100069b0(param_1,uVar11,s_Killed_unknown_protocol__1009038d);
        puVar12 = (undefined4 *)*puVar13;
        FUN_10058160(puVar13[1]);
        FUN_10055b20(param_1 + 0x30,puVar13);
        FUN_10052c10(puVar13);
        FUN_10057940(0,0x82,1);
        puVar13 = puVar12;
      }
    }
    else {
LAB_1000b2b8:
      puVar13 = (undefined4 *)*puVar13;
    }
  } while( true );
}

