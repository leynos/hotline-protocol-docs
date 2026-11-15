
/* WARNING: Removing unreachable block (ram,0x100171d4) */

void FUN_100170c0(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined1 *puVar1;
  bool bVar2;
  undefined4 uVar3;
  int iVar4;
  short sVar5;
  char cVar6;
  undefined1 auStack_b40 [128];
  ushort local_a80 [2];
  int local_a7c;
  int local_a78;
  int local_a74;
  undefined4 local_a70;
  undefined4 local_a6c;
  undefined4 local_a68;
  undefined4 local_a64;
  undefined4 local_a60;
  undefined4 local_a5c;
  undefined1 *local_a44;
  undefined1 *local_a2c;
  byte local_a28;
  char local_a27 [255];
  byte local_928;
  undefined1 auStack_927 [255];
  undefined1 local_828;
  undefined1 auStack_827 [2055];
  
  puVar1 = auStack_b40 + 0x80;
  uVar3 = FUN_10056b60(param_4,0xca,&local_828,0x800);
  local_928 = FUN_10056b60(param_4,0xc9,auStack_927,0xff);
  local_a7c = FUN_10007ee0(param_1,param_2);
  local_a78 = FUN_1002b0e0(local_a7c,&local_828,uVar3,&local_928,2,0);
  if (local_a78 == 0) {
LAB_1001715c:
    FUN_1000ef30(param_3,0x10091d9a,&local_928);
    FUN_1002b2f0(local_a78);
    if (local_a7c == 0) {
      return;
    }
    FUN_1002b2f0(local_a7c);
    return;
  }
  iVar4 = FUN_1002b250(local_a78);
  local_a74 = iVar4;
  FUN_1002cf90(iVar4,local_a80);
  if (local_a80[0] == 3) {
LAB_10017200:
    bVar2 = true;
  }
  else {
    if (local_a80[0] < 3) {
      if (local_a80[0] < 2) {
        if (local_a74 != 0) {
          FUN_1002b2f0(local_a74);
        }
        goto LAB_1001715c;
      }
    }
    else if (local_a80[0] == 5) goto LAB_10017200;
    bVar2 = false;
  }
  local_a44 = puVar1;
  if ((local_a80[0] != 6) && (sVar5 = FUN_100564c0(param_4,0xd2), sVar5 != 0)) {
    if (bVar2) {
      cVar6 = FUN_10008ab0(param_1,param_2,0x1d);
      if (cVar6 == '\0') {
        local_a70 = FUN_10056380(0,0);
        FUN_10056ae0(local_a70,100,0x10091dd7);
        FUN_10058a10(param_3,1);
        FUN_10058a70(param_3,local_a70);
        FUN_100563d0(local_a70);
        if (local_a74 != 0) {
          FUN_1002b2f0(local_a74);
        }
        FUN_1002b2f0(local_a78);
        if (local_a7c == 0) {
          return;
        }
        FUN_1002b2f0(local_a7c);
        return;
      }
    }
    else {
      cVar6 = FUN_10008ab0(param_1,param_2,0x1c);
      if (cVar6 == '\0') {
        local_a6c = FUN_10056380(0,0);
        FUN_10056ae0(local_a6c,100,0x10091e05);
        FUN_10058a10(param_3,1);
        FUN_10058a70(param_3,local_a6c);
        FUN_100563d0(local_a6c);
        if (local_a74 != 0) {
          FUN_1002b2f0(local_a74);
        }
        FUN_1002b2f0(local_a78);
        if (local_a7c == 0) {
          return;
        }
        FUN_1002b2f0(local_a7c);
        return;
      }
    }
    local_a2c = puVar1;
    FUN_10056c70(param_4,0xd2,&local_a28,0x100);
    if ((local_a28 == 1) && (local_a27[0] == '\0')) {
      local_a28 = 0;
    }
    FUN_1002c690(iVar4,local_a27,local_a28,0);
  }
  FUN_10056c70(param_4,0xd3,&local_a28,0x100);
  if ((local_a28 != 0) &&
     ((local_a28 != local_928 ||
      (cVar6 = FUN_1006cd80(auStack_927,local_a27,local_a28), cVar6 == '\0')))) {
    if (bVar2) {
      cVar6 = FUN_10008ab0(param_1,param_2,7);
      if (cVar6 == '\0') {
        local_a68 = FUN_10056380(0,0);
        FUN_10056ae0(local_a68,100,0x10091e31);
        FUN_10058a10(param_3,1);
        FUN_10058a70(param_3,local_a68);
        FUN_100563d0(local_a68);
        if (local_a74 != 0) {
          FUN_1002b2f0(local_a74);
        }
        FUN_1002b2f0(local_a78);
        if (local_a7c == 0) {
          return;
        }
        FUN_1002b2f0(local_a7c);
        return;
      }
    }
    else {
      cVar6 = FUN_10008ab0(param_1,param_2,3);
      if (cVar6 == '\0') {
        local_a64 = FUN_10056380(0,0);
        FUN_10056ae0(local_a64,100,0x10091e58);
        FUN_10058a10(param_3,1);
        FUN_10058a70(param_3,local_a64);
        FUN_100563d0(local_a64);
        if (local_a74 != 0) {
          FUN_1002b2f0(local_a74);
        }
        FUN_1002b2f0(local_a78);
        if (local_a7c == 0) {
          return;
        }
        FUN_1002b2f0(local_a7c);
        return;
      }
    }
    cVar6 = FUN_10008ab0(param_1,param_2,0x1e);
    if (cVar6 == '\0') {
      FUN_100539c0(&local_828,&local_928,local_928 + 1);
      FUN_100541e0(auStack_827,local_828,0);
      iVar4 = FUN_1006ce10(s_ECannot_get_file_list_because_th_1009075c + 0x46,8,auStack_827,
                           local_828);
      if (iVar4 != 0) {
        local_a60 = FUN_10056380(0,0);
        FUN_10056ae0(local_a60,100,0x10091e7d);
        FUN_10058a10(param_3,1);
        FUN_10058a70(param_3,local_a60);
        FUN_100563d0(local_a60);
        if (local_a74 != 0) {
          FUN_1002b2f0(local_a74);
        }
        FUN_1002b2f0(local_a78);
        if (local_a7c == 0) {
          return;
        }
        FUN_1002b2f0(local_a7c);
        return;
      }
    }
    local_a28 = FUN_1002c070(local_a27,local_a28,0);
    FUN_1002bc30(local_a78,&local_a28,0);
  }
  local_a5c = FUN_10056380(0,0);
  FUN_10058a70(param_3,local_a5c);
  FUN_100563d0(local_a5c);
  if (local_a74 != 0) {
    FUN_1002b2f0(local_a74);
  }
  FUN_1002b2f0(local_a78);
  if (local_a7c != 0) {
    FUN_1002b2f0(local_a7c);
  }
  return;
}

