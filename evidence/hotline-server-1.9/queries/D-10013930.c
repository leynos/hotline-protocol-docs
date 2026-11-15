
void FUN_10013930(int param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  undefined1 *puVar1;
  char cVar9;
  undefined4 uVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  uint uVar8;
  int iVar10;
  undefined8 uVar11;
  undefined1 auStack_c80 [128];
  char local_bc0 [4];
  undefined4 local_bbc;
  int local_bb8;
  int local_bb4;
  undefined4 local_bb0;
  undefined4 local_ba8;
  undefined4 local_ba4;
  undefined1 *local_b8c;
  undefined1 *local_b74;
  byte local_b38;
  undefined1 auStack_b37 [255];
  undefined1 local_a38;
  undefined1 auStack_a37 [511];
  undefined1 local_838;
  undefined1 auStack_837 [2055];
  
  puVar1 = auStack_c80 + 0x80;
  local_bbc = FUN_10056380(0,0);
  iVar10 = 0;
  cVar9 = FUN_10008ab0(param_1,param_2,0x26);
  if (cVar9 == '\0') {
    local_bb0 = FUN_10056380(0,0);
    FUN_10056ae0(local_bb0,100,0x1009130c);
    FUN_10058a10(param_3,1);
    FUN_10058a70(param_3,local_bb0);
    FUN_100563d0(local_bb0);
    FUN_100563d0(local_bbc);
    return;
  }
  uVar2 = FUN_10056b60(param_4,0xca,&local_838,0x800);
  FUN_10056c70(param_4,0xc9,&local_b38,0x100);
  local_b38 = FUN_1002c070(auStack_b37,local_b38,0);
  iVar3 = FUN_10056b90(param_4,0xdc);
  uVar4 = FUN_10056b90(param_4,0x6c);
  iVar5 = FUN_10056b90(param_4,0xcc);
  local_bb8 = FUN_10007ee0(param_1,param_2);
  iVar6 = FUN_1002b0e0(local_bb8,&local_838,uVar2,0,0x212,0);
  if (iVar6 == 0) {
    FUN_1000ef30(param_3,0x10091333,&local_b38);
    if (local_bb8 != 0) {
      FUN_1002b2f0(local_bb8);
    }
    FUN_100563d0(local_bbc);
    return;
  }
  local_bb4 = iVar6;
  cVar9 = FUN_10008ab0(param_1,param_2,0x19);
  if (cVar9 == '\0') {
    FUN_1002bce0(iVar6,&local_a38,0);
    FUN_100541e0(auStack_a37,local_a38,0);
    iVar7 = FUN_1006ce10(s_upload_1009105b,6,auStack_a37,local_a38);
    if ((iVar7 == 0) &&
       (iVar7 = FUN_1006ce10(s_ECannot_get_file_list_because_th_1009075c + 0x46,8,auStack_a37,
                             local_a38), iVar7 == 0)) {
      FUN_1000ef30(param_3,0x1009138d,&local_b38);
      if (local_bb4 != 0) {
        FUN_1002b2f0(local_bb4);
      }
      if (local_bb8 != 0) {
        FUN_1002b2f0(local_bb8);
      }
      FUN_100563d0(local_bbc);
      return;
    }
  }
  cVar9 = FUN_1002cff0(iVar6);
  if (cVar9 != '\0') {
    FUN_1000ef30(param_3,0x100913f6,&local_b38);
    if (local_bb4 != 0) {
      FUN_1002b2f0(local_bb4);
    }
    if (local_bb8 != 0) {
      FUN_1002b2f0(local_bb8);
    }
    FUN_100563d0(local_bbc);
    return;
  }
  local_b8c = puVar1;
  if (iVar5 == 1) {
    iVar5 = FUN_1002af80(iVar6,0,&local_b38,0x212,0);
    if (iVar5 == 0) {
      uVar2 = 0x10091456;
      goto LAB_10014018;
    }
    cVar9 = FUN_1002b750(iVar5,local_bc0);
    if ((cVar9 == '\0') || (local_bc0[0] == '\0')) {
      uVar2 = 0x1009149a;
      goto LAB_10014018;
    }
  }
  else {
    iVar5 = FUN_1002af80(iVar6,0,&local_b38,4,0);
    if (iVar5 == 0) {
      uVar2 = 0x100914c8;
      goto LAB_10014018;
    }
  }
  local_b74 = puVar1;
  uVar11 = FUN_1002d050(iVar6);
  uVar8 = (uint)((ulonglong)uVar11 >> 0x20);
  if ((0xfff82fff < uVar4) <= uVar8 &&
      (uint)((uint)uVar11 < uVar4 + 0x7d000) <= uVar8 - (0xfff82fff < uVar4)) {
    cVar9 = FUN_1002b750(iVar5,0);
    if (cVar9 == '\0') {
      FUN_1002b670(iVar5);
    }
    if (iVar3 != 0) {
      iVar10 = FUN_10052b70(0x58);
      *(uint *)(iVar10 + 0x18) = uVar4;
      *(int *)(iVar10 + 4) = iVar5;
      uVar4 = FUN_100046c0(param_1);
      *(uint *)(iVar10 + 0xc) = uVar4 & 0xfffffffe;
      uVar2 = FUN_10057d00();
      *(undefined4 *)(iVar10 + 0x10) = uVar2;
      *(int *)(iVar10 + 0x30) = param_2;
      *(undefined2 *)(iVar10 + 0x34) = *(undefined2 *)(param_2 + 0x14);
      *(byte *)(iVar10 + 0x38) = local_b38;
      if (0x1f < local_b38) {
        *(undefined1 *)(iVar10 + 0x38) = 0x1f;
      }
      FUN_100539c0(iVar10 + 0x39,auStack_b37,*(undefined1 *)(iVar10 + 0x38));
      *(int *)(iVar10 + 0x1c) = iVar3;
      FUN_100554e0(param_1 + 0x74,iVar10);
    }
    if (iVar10 == 0) {
      local_ba8 = FUN_10056380(0,0);
      FUN_10058a70(param_3,local_ba8);
      FUN_100563d0(local_ba8);
      FUN_1002b2f0(iVar5);
    }
    else {
      FUN_100568b0(local_bbc,0x6b,iVar10 + 0xc,4);
      FUN_10058a70(param_3,local_bbc);
    }
    *(int *)(param_1 + 0x438) = *(int *)(param_1 + 0x438) + 1;
    FUN_100068e0(param_1,param_2,0x100915ae,&local_b38);
    FUN_100044a0(param_1);
    FUN_10006d10(param_1,param_2,&local_b38);
    if (local_bb4 != 0) {
      FUN_1002b2f0(local_bb4);
    }
    if (local_bb8 != 0) {
      FUN_1002b2f0(local_bb8);
    }
    FUN_100563d0(local_bbc);
    return;
  }
  FUN_100068e0(param_1,param_2,s_Not_enough_free_disk_space_for_f_1009152b);
  uVar2 = 0x10091558;
LAB_10014018:
  FUN_1002b2f0(iVar5);
  local_838 = FUN_10054180(auStack_837,0xff,uVar2,&local_b38);
  local_ba4 = FUN_10056380(0,0);
  FUN_10056ae0(local_ba4,100,&local_838);
  FUN_10058a10(param_3,1);
  FUN_10058a70(param_3,local_ba4);
  FUN_100563d0(local_ba4);
  if (local_bb4 != 0) {
    FUN_1002b2f0(local_bb4);
  }
  if (local_bb8 != 0) {
    FUN_1002b2f0(local_bb8);
  }
  FUN_100563d0(local_bbc);
  return;
}

