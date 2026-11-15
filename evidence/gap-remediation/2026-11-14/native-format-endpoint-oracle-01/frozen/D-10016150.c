
void FUN_10016150(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  int *piVar1;
  char *pcVar2;
  undefined4 uVar3;
  char cVar8;
  undefined4 uVar4;
  short sVar7;
  int iVar5;
  int iVar6;
  uint uVar9;
  uint uVar10;
  undefined1 *puVar11;
  byte local_ea0 [16];
  undefined1 local_e90;
  undefined1 auStack_e8f [31];
  undefined1 local_e70;
  undefined1 auStack_e6f [63];
  undefined1 local_e30 [512];
  undefined1 local_c30 [512];
  undefined1 local_a30 [512];
  undefined1 local_830 [512];
  undefined1 local_630 [512];
  undefined1 auStack_430 [1036];
  
  uVar3 = FUN_10056380(0,0);
  cVar8 = FUN_10008a90(param_1,param_2,0x18);
  if (cVar8 == '\0') {
    uVar4 = FUN_10056380(0,0);
    FUN_10056ae0(uVar4,100,s__You_are_not_allowed_to_get_clie_10091b11);
    FUN_10058a10(param_3,1);
    FUN_10058a70(param_3,uVar4);
    FUN_100563d0(uVar4);
    FUN_100563d0(uVar3);
  }
  else {
    sVar7 = FUN_10056b90(param_4,0x67);
    iVar5 = FUN_10004730(param_1,sVar7);
    if (iVar5 == 0) {
      uVar4 = FUN_10056380(0,0);
      FUN_10056ae0(uVar4,100,s__You_are_not_allowed_to_get_clie_10091b11 + 0x2f);
      FUN_10058a10(param_3,1);
      FUN_10058a70(param_3,uVar4);
      FUN_100563d0(uVar4);
      FUN_100563d0(uVar3);
    }
    else {
      puVar11 = local_e30;
      uVar10 = 0;
      while (uVar10 = uVar10 + 1, uVar10 <= *(uint *)(param_1 + 0x3c)) {
        piVar1 = *(int **)(*(int *)(param_1 + 0x38) + uVar10 * 4 + -4);
        if (*(short *)(piVar1 + 10) == sVar7) {
          if (local_c30 + -(int)puVar11 < (undefined1 *)0x28) break;
          if ((*piVar1 == 0) || (piVar1[5] == 0)) {
            uVar9 = 0;
          }
          else {
            iVar6 = FUN_1006e040(*piVar1);
            uVar9 = (uint)(piVar1[6] - iVar6) / ((uint)piVar1[5] / 100);
            if (100 < uVar9) {
              uVar9 = 100;
            }
          }
          cVar8 = FUN_10053c10(local_ea0 + 1,0xf,uVar9,0);
          local_ea0[0] = cVar8 + 1;
          local_ea0[local_ea0[0]] = 0x25;
          local_e90 = FUN_10053d50(piVar1[5],auStack_e8f,0x1f,1);
          iVar6 = FUN_10054180(puVar11,local_c30 + -(int)puVar11,
                               s__You_are_not_allowed_to_get_clie_10091b11 + 0x73,(int)piVar1 + 0x2b
                               ,local_ea0,&local_e90);
          puVar11 = puVar11 + iVar6;
        }
      }
      if (puVar11 == local_e30) {
        *puVar11 = 0x4e;
        puVar11[1] = 0x6f;
        puVar11[2] = 0x6e;
        puVar11[3] = 0x65;
        puVar11[4] = 0x2e;
        puVar11[5] = 0xd;
        puVar11 = puVar11 + 6;
      }
      *puVar11 = 0;
      puVar11 = local_c30;
      uVar10 = 0;
      while (uVar10 = uVar10 + 1, uVar10 <= *(uint *)(param_1 + 0x48)) {
        piVar1 = *(int **)(*(int *)(param_1 + 0x44) + uVar10 * 4 + -4);
        if (*(short *)(piVar1 + 0xc) == sVar7) {
          if (local_a30 + -(int)puVar11 < (undefined1 *)0x28) break;
          if ((*piVar1 == 0) || (piVar1[5] == 0)) {
            uVar9 = 0;
          }
          else {
            iVar6 = FUN_1006e040(*piVar1);
            uVar9 = (uint)(piVar1[6] - iVar6) / ((uint)piVar1[5] / 100);
            if (100 < uVar9) {
              uVar9 = 100;
            }
          }
          cVar8 = FUN_10053c10(local_ea0 + 1,0xf,uVar9,0);
          local_ea0[0] = cVar8 + 1;
          local_ea0[local_ea0[0]] = 0x25;
          local_e90 = FUN_10053d50(piVar1[5],auStack_e8f,0x1f,1);
          iVar6 = FUN_10054180(puVar11,local_a30 + -(int)puVar11,
                               s__You_are_not_allowed_to_get_clie_10091b11 + 0x73,piVar1 + 0xe,
                               local_ea0,&local_e90);
          puVar11 = puVar11 + iVar6;
        }
      }
      if (puVar11 == local_c30) {
        *puVar11 = 0x4e;
        puVar11[1] = 0x6f;
        puVar11[2] = 0x6e;
        puVar11[3] = 0x65;
        puVar11[4] = 0x2e;
        puVar11[5] = 0xd;
        puVar11 = puVar11 + 6;
      }
      *puVar11 = 0;
      puVar11 = local_a30;
      uVar10 = 0;
      while (uVar10 = uVar10 + 1, uVar10 <= *(uint *)(param_1 + 0x6c)) {
        piVar1 = *(int **)(*(int *)(param_1 + 0x68) + uVar10 * 4 + -4);
        if (*(short *)(piVar1 + 7) == sVar7) {
          if (local_830 + -(int)puVar11 < (undefined1 *)0x28) break;
          if ((*piVar1 == 0) || (piVar1[5] == 0)) {
            uVar9 = 0;
          }
          else {
            uVar9 = (uint)piVar1[4] / ((uint)piVar1[5] / 100);
            if (100 < uVar9) {
              uVar9 = 100;
            }
          }
          cVar8 = FUN_10053c10(local_ea0 + 1,0xf,uVar9,0);
          local_ea0[0] = cVar8 + 1;
          local_ea0[local_ea0[0]] = 0x25;
          local_e90 = FUN_10053d50(piVar1[5],auStack_e8f,0x1f,1);
          iVar6 = FUN_10054180(puVar11,local_830 + -(int)puVar11,
                               s__You_are_not_allowed_to_get_clie_10091b11 + 0x73,(int)piVar1 + 0x1e
                               ,local_ea0,&local_e90);
          puVar11 = puVar11 + iVar6;
        }
      }
      if (puVar11 == local_a30) {
        *puVar11 = 0x4e;
        puVar11[1] = 0x6f;
        puVar11[2] = 0x6e;
        puVar11[3] = 0x65;
        puVar11[4] = 0x2e;
        puVar11[5] = 0xd;
        puVar11 = puVar11 + 6;
      }
      *puVar11 = 0;
      puVar11 = local_830;
      uVar10 = 0;
      while (uVar10 = uVar10 + 1, uVar10 <= *(uint *)(param_1 + 0x78)) {
        piVar1 = *(int **)(*(int *)(param_1 + 0x74) + uVar10 * 4 + -4);
        if (*(short *)(piVar1 + 0xd) == sVar7) {
          if (local_630 + -(int)puVar11 < (undefined1 *)0x28) break;
          if ((*piVar1 == 0) || (piVar1[6] == 0)) {
            uVar9 = 0;
          }
          else {
            uVar9 = (uint)piVar1[5] / ((uint)piVar1[6] / 100);
            if (100 < uVar9) {
              uVar9 = 100;
            }
          }
          cVar8 = FUN_10053c10(local_ea0 + 1,0xf,uVar9,0);
          local_ea0[0] = cVar8 + 1;
          local_ea0[local_ea0[0]] = 0x25;
          local_e90 = FUN_10053d50(piVar1[6],auStack_e8f,0x1f,1);
          iVar6 = FUN_10054180(puVar11,local_630 + -(int)puVar11,
                               s__You_are_not_allowed_to_get_clie_10091b11 + 0x73,piVar1 + 0xe,
                               local_ea0,&local_e90);
          puVar11 = puVar11 + iVar6;
        }
      }
      if (puVar11 == local_830) {
        *puVar11 = 0x4e;
        puVar11[1] = 0x6f;
        puVar11[2] = 0x6e;
        puVar11[3] = 0x65;
        puVar11[4] = 0x2e;
        puVar11[5] = 0xd;
        puVar11 = puVar11 + 6;
      }
      *puVar11 = 0;
      puVar11 = local_630;
      uVar10 = 0;
      while (uVar10 = uVar10 + 1, uVar10 <= *(uint *)(param_1 + 0x54)) {
        pcVar2 = *(char **)(*(int *)(param_1 + 0x50) + uVar10 * 4 + -4);
        if (*pcVar2 == '\0') {
          if (*(short *)(*(int *)(pcVar2 + 8) + 0x30) == sVar7) {
            if (auStack_430 + -(int)puVar11 < (undefined1 *)0x28) break;
            iVar6 = FUN_10054180(puVar11,auStack_430 + -(int)puVar11,s____21_21s__Folder__10091bad,
                                 *(int *)(pcVar2 + 8) + 0x38);
            puVar11 = puVar11 + iVar6;
          }
        }
        else if (*(short *)(*(int *)(pcVar2 + 8) + 0x28) == sVar7) {
          if (auStack_430 + -(int)puVar11 < (undefined1 *)0x28) break;
          iVar6 = FUN_10054180(puVar11,auStack_430 + -(int)puVar11,s____21_21s__File__10091b9b,
                               *(int *)(pcVar2 + 8) + 0x2b);
          puVar11 = puVar11 + iVar6;
        }
      }
      if (puVar11 == local_630) {
        *puVar11 = 0x4e;
        puVar11[1] = 0x6f;
        puVar11[2] = 0x6e;
        puVar11[3] = 0x65;
        puVar11[4] = 0x2e;
        puVar11[5] = 0xd;
        puVar11 = puVar11 + 6;
      }
      *puVar11 = 0;
      uVar4 = FUN_10058270(*(undefined4 *)(iVar5 + 4));
      local_e70 = FUN_1006d550(uVar4,auStack_e6f,0x3f);
      uVar4 = FUN_10054180(auStack_430,0x400,s_Nickname____s_Name____s_Account__10091bc1,
                           iVar5 + 0x38,iVar5 + 0x58,iVar5 + 0x78,&local_e70,local_e30);
      FUN_100568b0(uVar3,0x65,auStack_430,uVar4);
      FUN_10056ae0(uVar3,0x66,iVar5 + 0x38);
      FUN_10058a70(param_3,uVar3);
      FUN_100563d0(uVar3);
    }
  }
  return;
}

