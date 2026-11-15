
void FUN_100130f0(int param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  undefined1 *puVar1;
  undefined4 uVar2;
  char cVar11;
  undefined4 uVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  undefined4 uVar9;
  undefined4 uVar10;
  undefined8 uVar12;
  undefined1 auStack_d80 [128];
  int local_cbc;
  int local_cb8;
  int local_cb4;
  int local_cb0;
  undefined4 local_cac;
  undefined4 local_ca8;
  undefined4 local_ca0;
  undefined1 *local_c84;
  undefined1 *local_c6c;
  byte local_c30;
  undefined1 auStack_c2f [255];
  undefined1 local_b30;
  undefined1 auStack_b2f [255];
  undefined1 auStack_a30 [512];
  undefined1 local_830;
  undefined1 auStack_82f [2047];
  
  puVar1 = auStack_d80 + 0x80;
  uVar2 = FUN_10056380(0,0);
  cVar11 = FUN_10008ab0(param_1,param_2,1);
  if (cVar11 == '\0') {
    local_ca8 = FUN_10056380(0,0);
    FUN_10056ae0(local_ca8,100,0x10090fde);
    FUN_10058a10(param_3,1);
    FUN_10058a70(param_3,local_ca8);
    FUN_100563d0(local_ca8);
    FUN_100563d0(uVar2);
    return;
  }
  uVar3 = FUN_10056b60(param_4,0xca,&local_830,0x800);
  FUN_10056c70(param_4,0xc9,&local_c30,0x100);
  iVar4 = FUN_10056b90(param_4,0xcc);
  uVar5 = FUN_10056b90(param_4,0x6c);
  local_c30 = FUN_1002c070(auStack_c2f,local_c30,0);
  local_cb4 = FUN_10007ee0(param_1,param_2);
  iVar6 = FUN_1002b0e0(local_cb4,&local_830,uVar3,0,0x212,0);
  if (iVar6 == 0) {
    FUN_1000ef30(param_3,0x10091003,&local_c30);
    if (local_cb4 != 0) {
      FUN_1002b2f0(local_cb4);
    }
    FUN_100563d0(uVar2);
    return;
  }
  local_cb0 = iVar6;
  cVar11 = FUN_10008ab0(param_1,param_2,0x19);
  if (cVar11 == '\0') {
    local_b30 = FUN_1006e820(&local_830,uVar3,auStack_b2f,0xff,0,0);
    iVar7 = FUN_10053b30(s_upload_1009105b,6,auStack_b2f,local_b30);
    if ((iVar7 == 0) &&
       (iVar7 = FUN_10053b30(s_ECannot_get_file_list_because_th_1009075c + 0x46,8,auStack_b2f,
                             local_b30), iVar7 == 0)) {
      FUN_1000ef30(param_3,0x10091062,&local_c30);
      if (local_cb0 != 0) {
        FUN_1002b2f0(local_cb0);
      }
      if (local_cb4 != 0) {
        FUN_1002b2f0(local_cb4);
      }
      FUN_100563d0(uVar2);
      return;
    }
  }
  cVar11 = FUN_1002cff0(iVar6);
  if (cVar11 != '\0') {
    FUN_1000ef30(param_3,0x100910c9,&local_c30);
    if (local_cb0 != 0) {
      FUN_1002b2f0(local_cb0);
    }
    if (local_cb4 != 0) {
      FUN_1002b2f0(local_cb4);
    }
    FUN_100563d0(uVar2);
    return;
  }
  FUN_100539c0(auStack_a30,&local_c30,local_c30 + 1);
  local_c84 = puVar1;
  if (iVar4 == 1) {
    iVar7 = FUN_1002af80(iVar6,0,auStack_a30,0x20a,0);
    if (iVar7 == 0) {
      uVar3 = 0x10091127;
    }
    else {
      FUN_1002c800(iVar7,&local_cbc,&local_cb8);
      if ((local_cbc == 0x48546674) && (local_cb8 == 0x48544c43)) {
LAB_100134f8:
        iVar6 = FUN_10052b70(0x40);
        *(uint *)(iVar6 + 0x14) = uVar5;
        *(int *)(iVar6 + 4) = iVar7;
        if (iVar4 == 1) {
          uVar3 = FUN_1002db60(iVar7);
          local_cac = uVar3;
          uVar9 = FUN_10053290();
          uVar10 = FUN_10052f80(uVar3);
          FUN_100568b0(uVar2,0xcb,uVar9,uVar10);
          FUN_10053310(local_cac);
          FUN_10052e90(uVar3);
        }
        else {
          FUN_1002b370(iVar7,0x48546674,0x48544c43);
          FUN_1002d9e0(iVar7);
        }
        uVar5 = FUN_100046c0(param_1);
        *(uint *)(iVar6 + 8) = uVar5 & 0xfffffffe;
        uVar3 = FUN_10057d00();
        *(undefined4 *)(iVar6 + 0xc) = uVar3;
        *(int *)(iVar6 + 0x18) = param_2;
        *(undefined2 *)(iVar6 + 0x1c) = *(undefined2 *)(param_2 + 0x14);
        *(byte *)(iVar6 + 0x1e) = local_c30;
        if (0x1f < local_c30) {
          *(undefined1 *)(iVar6 + 0x1e) = 0x1f;
        }
        FUN_100539c0(iVar6 + 0x1f,auStack_c2f,*(undefined1 *)(iVar6 + 0x1e));
        FUN_100554e0(param_1 + 0x68,iVar6);
        FUN_100568b0(uVar2,0x6b,iVar6 + 8,4);
        FUN_10058a70(param_3,uVar2);
        *(int *)(param_1 + 0x438) = *(int *)(param_1 + 0x438) + 1;
        FUN_100068e0(param_1,param_2,0x100912ff,&local_c30);
        FUN_100044a0(param_1);
        FUN_10006d10(param_1,param_2,&local_c30);
        if (local_cb0 != 0) {
          FUN_1002b2f0(local_cb0);
        }
        if (local_cb4 != 0) {
          FUN_1002b2f0(local_cb4);
        }
        FUN_100563d0(uVar2);
        return;
      }
      uVar3 = 0x10091169;
    }
  }
  else {
    iVar7 = FUN_1002af80(iVar6,0,&local_c30,4,0);
    if (iVar7 == 0) {
      uVar3 = 0x100911b8;
    }
    else {
      local_c6c = puVar1;
      uVar12 = FUN_1002d050(iVar6);
      uVar8 = (uint)((ulonglong)uVar12 >> 0x20);
      if ((0xfff82fff < uVar5) <= uVar8 &&
          (uint)((uint)uVar12 < uVar5 + 0x7d000) <= uVar8 - (0xfff82fff < uVar5)) goto LAB_100134f8;
      FUN_100068e0(param_1,param_2,s_Not_enough_free_disk_space_for_u_10091219);
      uVar3 = 0x1009123f;
    }
  }
  FUN_1002b2f0(iVar7);
  local_830 = FUN_10054180(auStack_82f,0xff,uVar3,&local_c30);
  local_ca0 = FUN_10056380(0,0);
  FUN_10056ae0(local_ca0,100,&local_830);
  FUN_10058a10(param_3,1);
  FUN_10058a70(param_3,local_ca0);
  FUN_100563d0(local_ca0);
  if (local_cb0 != 0) {
    FUN_1002b2f0(local_cb0);
  }
  if (local_cb4 != 0) {
    FUN_1002b2f0(local_cb4);
  }
  FUN_100563d0(uVar2);
  return;
}

