
void FUN_10012850(int param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  char cVar9;
  undefined4 uVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  undefined4 uVar7;
  undefined1 *puVar8;
  uint uVar10;
  undefined1 auStack_d50 [128];
  char local_c90 [2];
  undefined2 local_c8e;
  undefined2 local_c8c [2];
  undefined4 local_c88;
  int local_c84;
  undefined1 auStack_c80 [4];
  undefined4 local_c7c;
  undefined4 local_c78;
  undefined4 local_c74;
  undefined1 *local_c5c;
  undefined1 *local_c44;
  byte local_c40;
  undefined1 auStack_c3f [255];
  undefined1 local_b40;
  undefined1 auStack_b3f [255];
  undefined1 auStack_a40 [512];
  undefined1 auStack_840 [2056];
  
  local_c88 = FUN_10056380(0,0);
  cVar9 = FUN_10008ab0(param_1,param_2,0x27);
  if (cVar9 == '\0') {
    local_c7c = FUN_10056380(0,0);
    FUN_10056ae0(local_c7c,100,0x10090f19);
    FUN_10058a10(param_3,1);
    FUN_10058a70(param_3,local_c7c);
    FUN_100563d0(local_c7c);
    FUN_100563d0(local_c88);
  }
  else {
    local_c40 = FUN_10056b60(param_4,0xc9,auStack_c3f,0xff);
    uVar1 = FUN_10056b60(param_4,0xca,auStack_840,0x800);
    uVar10 = 0;
    uVar2 = *(int *)(param_1 + 0x3c) + *(int *)(param_1 + 0x48);
    if (*(ushort *)(param_1 + 0xa4) <= uVar2) {
      uVar10 = (uVar2 - *(ushort *)(param_1 + 0xa4)) + 1;
    }
    uVar2 = 0;
    uVar3 = FUN_10006700(param_1,*(undefined2 *)(param_2 + 0x14));
    if ((uint)*(ushort *)(param_1 + 0xa6) <= (uVar3 & 0xffff)) {
      uVar2 = ((uVar3 & 0xffff) - (uint)*(ushort *)(param_1 + 0xa6)) + 1;
    }
    if (uVar2 < uVar10) {
      uVar2 = uVar10;
    }
    FUN_10056b90(param_4,0xcc);
    FUN_10056b60(param_4,0xcb,auStack_a40,0x200);
    local_c5c = auStack_d50 + 0x80;
    local_c84 = FUN_10007ee0(param_1,param_2);
    iVar4 = FUN_1002b0e0(local_c84,auStack_840,uVar1,&local_c40,0x212,0);
    if (iVar4 == 0) {
      local_b40 = FUN_10054180(auStack_b3f,0xff,0x10090f42,&local_c40);
      local_c78 = FUN_10056380(0,0);
      FUN_10056ae0(local_c78,100,&local_b40);
      FUN_10058a10(param_3,1);
      FUN_10058a70(param_3,local_c78);
      FUN_100563d0(local_c78);
      if (local_c84 != 0) {
        FUN_1002b2f0(local_c84);
      }
      FUN_100563d0(local_c88);
    }
    else {
      uVar10 = FUN_10008ab0(param_1,param_2,0x1e);
      if ((uVar10 & 0xff) == 0) {
        FUN_100541e0(auStack_c3f,local_c40,0);
        FUN_100541e0(auStack_840,uVar1,0);
        iVar5 = FUN_1006ce10(s_ECannot_get_file_list_because_th_1009075c + 0x46,8,auStack_c3f,
                             local_c40);
        if ((iVar5 != 0) ||
           (iVar5 = FUN_1006ce10(s_ECannot_get_file_list_because_th_1009075c + 0x46,8,auStack_840,
                                 uVar1), iVar5 != 0)) {
          local_b40 = FUN_10054180(auStack_b3f,0xff,0x10090f7a,&local_c40);
          local_c74 = FUN_10056380(0,0);
          FUN_10056ae0(local_c74,100,&local_b40);
          FUN_10058a10(param_3,1);
          FUN_10058a70(param_3,local_c74);
          FUN_100563d0(local_c74);
          FUN_1002b2f0(iVar4);
          if (local_c84 != 0) {
            FUN_1002b2f0(local_c84);
          }
          FUN_100563d0(local_c88);
          return;
        }
      }
      iVar5 = FUN_10052b70(0x58);
      if (local_c84 != 0) {
        FUN_1002b2f0(local_c84);
      }
      local_c44 = auStack_d50 + 0x80;
      iVar6 = FUN_1006d260(0x18);
      if (iVar6 != 0) {
        FUN_10026480(iVar6,iVar4,0,uVar10);
      }
      *(int *)(iVar5 + 4) = iVar6;
      uVar1 = FUN_10026ea0(iVar6);
      local_c8e = 0xffff;
      local_c8c[0] = 0;
      local_c90[0] = '\0';
      iVar4 = FUN_100273a0(*(undefined4 *)(iVar5 + 4),auStack_c80,&local_c8e,local_c8c,local_c90);
      if ((iVar4 == 0) || (local_c90[0] == '\0')) {
        FUN_10001bd0(s_corrupt_folder_hierarchy__10090fc4);
      }
      iVar4 = FUN_10026a20(*(undefined4 *)(iVar5 + 4));
      iVar4 = iVar4 + -1;
      if (iVar4 == 0) {
        FUN_10026670(*(undefined4 *)(iVar5 + 4),1);
        FUN_10052c10(iVar5);
        iVar5 = 0;
      }
      else {
        *(undefined4 *)(iVar5 + 0x14) = uVar1;
        *(undefined4 *)(iVar5 + 0x24) = 0x19000;
        uVar10 = FUN_100046c0(param_1);
        *(uint *)(iVar5 + 0xc) = uVar10 | 1;
        uVar7 = FUN_10057d00();
        *(undefined4 *)(iVar5 + 0x10) = uVar7;
        *(int *)(iVar5 + 0x2c) = param_2;
        *(undefined2 *)(iVar5 + 0x30) = *(undefined2 *)(param_2 + 0x14);
        *(byte *)(iVar5 + 0x38) = local_c40;
        if (0x1f < local_c40) {
          *(undefined1 *)(iVar5 + 0x38) = 0x1f;
        }
        FUN_100539c0(iVar5 + 0x39,auStack_c3f,*(undefined1 *)(iVar5 + 0x38));
        if (uVar2 == 0) {
          FUN_100554e0(param_1 + 0x44,iVar5);
        }
        else {
          uVar2 = uVar2 + *(int *)(param_1 + 0x54);
          puVar8 = (undefined1 *)FUN_10052b70(0xc);
          *puVar8 = 0;
          *(uint *)(puVar8 + 4) = uVar2;
          *(int *)(puVar8 + 8) = iVar5;
          FUN_100554e0(param_1 + 0x50,puVar8);
        }
      }
      if (iVar5 == 0) {
        FUN_10056a90(local_c88,0x6c,uVar1);
        FUN_10056a90(local_c88,0xdc,iVar4);
        FUN_10058a70(param_3,local_c88);
      }
      else {
        FUN_10056a90(local_c88,0x6c,uVar1);
        FUN_10056a90(local_c88,0xdc,iVar4);
        FUN_100568b0(local_c88,0x6b,iVar5 + 0xc,4);
        if (uVar2 != 0) {
          FUN_10056a90(local_c88,0x74,uVar2);
        }
        FUN_10058a70(param_3,local_c88);
        *(int *)(param_1 + 0x434) = *(int *)(param_1 + 0x434) + 1;
        FUN_100068e0(param_1,param_2,0x10090f0a,&local_c40);
        FUN_100044a0(param_1);
        FUN_10006ba0(param_1,param_2,&local_c40);
      }
      FUN_100563d0(local_c88);
    }
  }
  return;
}

