
void FUN_100121a0(int param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  char cVar13;
  undefined4 uVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  undefined4 uVar11;
  undefined1 *puVar12;
  uint uVar14;
  byte local_c40;
  undefined1 auStack_c3f [255];
  undefined1 local_b40;
  undefined1 auStack_b3f [255];
  undefined1 auStack_a40 [512];
  undefined1 auStack_840 [2060];
  
  uVar1 = FUN_10056380(0,0);
  cVar13 = FUN_10008ab0(param_1,param_2,2);
  if (cVar13 == '\0') {
    uVar2 = FUN_10056380(0,0);
    FUN_10056ae0(uVar2,100,0x10090e6f);
    FUN_10058a10(param_3,1);
    FUN_10058a70(param_3,uVar2);
    FUN_100563d0(uVar2);
    FUN_100563d0(uVar1);
  }
  else {
    local_c40 = FUN_10056b60(param_4,0xc9,auStack_c3f,0xff);
    uVar2 = FUN_10056b60(param_4,0xca,auStack_840,0x800);
    uVar14 = 0;
    uVar3 = *(int *)(param_1 + 0x3c) + *(int *)(param_1 + 0x48);
    if (*(ushort *)(param_1 + 0xa4) <= uVar3) {
      uVar14 = (uVar3 - *(ushort *)(param_1 + 0xa4)) + 1;
    }
    uVar3 = 0;
    uVar4 = FUN_10006700(param_1,*(undefined2 *)(param_2 + 0x14));
    if ((uint)*(ushort *)(param_1 + 0xa6) <= (uVar4 & 0xffff)) {
      uVar3 = ((uVar4 & 0xffff) - (uint)*(ushort *)(param_1 + 0xa6)) + 1;
    }
    if (uVar3 < uVar14) {
      uVar3 = uVar14;
    }
    iVar5 = FUN_10056b90(param_4,0xcc);
    iVar6 = FUN_10056b60(param_4,0xcb,auStack_a40,0x200);
    iVar7 = FUN_10007ee0(param_1,param_2);
    iVar8 = FUN_1002b0e0(iVar7,auStack_840,uVar2,&local_c40,0x20a,0);
    if (iVar8 == 0) {
      local_b40 = FUN_10054180(auStack_b3f,0xff,0x10090e96,&local_c40);
      uVar2 = FUN_10056380(0,0);
      FUN_10056ae0(uVar2,100,&local_b40);
      FUN_10058a10(param_3,1);
      FUN_10058a70(param_3,uVar2);
      FUN_100563d0(uVar2);
      if (iVar7 != 0) {
        FUN_1002b2f0(iVar7);
      }
      FUN_100563d0(uVar1);
    }
    else {
      cVar13 = FUN_10008ab0(param_1,param_2,0x1e);
      if (cVar13 == '\0') {
        FUN_1002bdd0(iVar8,&local_b40,0);
        FUN_100541e0(auStack_b3f,local_b40,0);
        FUN_100541e0(auStack_840,uVar2,0);
        iVar9 = FUN_1006ce10(s_ECannot_get_file_list_because_th_1009075c + 0x46,8,auStack_b3f,
                             local_b40);
        if ((iVar9 != 0) ||
           (iVar9 = FUN_1006ce10(s_ECannot_get_file_list_because_th_1009075c + 0x46,8,auStack_840,
                                 uVar2), iVar9 != 0)) {
          local_b40 = FUN_10054180(auStack_b3f,0xff,0x10090ecc,&local_c40);
          uVar2 = FUN_10056380(0,0);
          FUN_10056ae0(uVar2,100,&local_b40);
          FUN_10058a10(param_3,1);
          FUN_10058a70(param_3,uVar2);
          FUN_100563d0(uVar2);
          FUN_1002b2f0(iVar8);
          if (iVar7 != 0) {
            FUN_1002b2f0(iVar7);
          }
          FUN_100563d0(uVar1);
          return;
        }
      }
      iVar9 = FUN_1002c4d0(iVar8,0);
      if ((iVar5 == 2) && (iVar9 == 0)) {
        FUN_10056a90(uVar1,0x6c,0);
        FUN_10058a70(param_3,uVar1);
        FUN_1002b2f0(iVar8);
        if (iVar7 != 0) {
          FUN_1002b2f0(iVar7);
        }
        FUN_100563d0(uVar1);
      }
      else {
        iVar10 = FUN_10052b70(0x4c);
        *(int *)(iVar10 + 4) = iVar8;
        if (iVar5 == 2) {
          *(undefined1 *)(iVar10 + 0x2a) = 1;
          FUN_1002c220(iVar8,0x21);
          uVar2 = FUN_1002c4d0(iVar8,0);
          *(undefined4 *)(iVar10 + 0x14) = uVar2;
        }
        else {
          if (iVar6 == 0) {
            FUN_1002d470(iVar8);
          }
          else {
            FUN_1002d650(iVar8,auStack_a40,iVar6);
          }
          uVar2 = FUN_1002d7b0(iVar8);
          *(undefined4 *)(iVar10 + 0x14) = uVar2;
        }
        *(undefined4 *)(iVar10 + 0x1c) = 0x19000;
        uVar14 = FUN_100046c0(param_1);
        *(uint *)(iVar10 + 8) = uVar14 | 1;
        uVar11 = FUN_10057d00();
        *(undefined4 *)(iVar10 + 0xc) = uVar11;
        *(int *)(iVar10 + 0x24) = param_2;
        *(undefined2 *)(iVar10 + 0x28) = *(undefined2 *)(param_2 + 0x14);
        *(byte *)(iVar10 + 0x2b) = local_c40;
        if (0x1f < local_c40) {
          *(undefined1 *)(iVar10 + 0x2b) = 0x1f;
        }
        FUN_100539c0(iVar10 + 0x2c,auStack_c3f,*(undefined1 *)(iVar10 + 0x2b));
        if (uVar3 == 0) {
          FUN_100554e0(param_1 + 0x38,iVar10);
          iVar5 = 0;
        }
        else {
          iVar5 = uVar3 + *(int *)(param_1 + 0x54);
          puVar12 = (undefined1 *)FUN_10052b70(0xc);
          *puVar12 = 1;
          *(int *)(puVar12 + 4) = iVar5;
          *(int *)(puVar12 + 8) = iVar10;
          FUN_100554e0(param_1 + 0x50,puVar12);
        }
        if (iVar7 != 0) {
          FUN_1002b2f0(iVar7);
        }
        FUN_10056a90(uVar1,0x6c,uVar2);
        FUN_10056a90(uVar1,0xcf,iVar9);
        FUN_100568b0(uVar1,0x6b,iVar10 + 8,4);
        if (iVar5 != 0) {
          FUN_10056a90(uVar1,0x74,iVar5);
        }
        FUN_10058a70(param_3,uVar1);
        *(int *)(param_1 + 0x434) = *(int *)(param_1 + 0x434) + 1;
        if (*(char *)(iVar10 + 0x2a) == '\0') {
          uVar2 = 0x10090f0a;
        }
        else {
          uVar2 = 0x10090eff;
        }
        FUN_100068e0(param_1,param_2,uVar2,&local_c40);
        FUN_100044a0(param_1);
        FUN_10006ba0(param_1,param_2,&local_c40);
        FUN_100563d0(uVar1);
      }
    }
  }
  return;
}

