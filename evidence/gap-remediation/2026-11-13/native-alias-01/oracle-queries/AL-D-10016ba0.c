
/* WARNING: Removing unreachable block (ram,0x10016cd4) */

void FUN_10016ba0(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  ushort local_a50 [2];
  undefined4 local_a4c;
  int local_a48;
  int local_a44;
  int local_a40;
  int local_a3c;
  int local_a38;
  undefined1 auStack_a30 [8];
  undefined1 auStack_a28 [8];
  undefined1 local_a20;
  int local_a1f [63];
  undefined1 local_920;
  undefined1 auStack_91f [255];
  undefined1 auStack_820 [2056];
  
  local_a4c = FUN_10056380(0,0);
  uVar1 = FUN_10056b60(param_4,0xca,auStack_820,0x800);
  local_920 = FUN_10056b60(param_4,0xc9,auStack_91f,0xff);
  local_a40 = FUN_10007ee0(param_1,param_2);
  local_a3c = FUN_1002b0e0(local_a40,auStack_820,uVar1,&local_920,2,0);
  if (local_a3c == 0) {
LAB_10016c4c:
    FUN_1000ef30(param_3,0x10091cc0,&local_920);
    FUN_1002b2f0(local_a3c);
    if (local_a40 != 0) {
      FUN_1002b2f0(local_a40);
    }
    FUN_100563d0(local_a4c);
    return;
  }
  iVar2 = FUN_1002b250(local_a3c);
  local_a38 = iVar2;
  FUN_1002cf90(iVar2,local_a50);
  if (local_a50[0] != 4) {
    if (local_a50[0] < 4) {
      if (local_a50[0] == 2) goto LAB_10016d98;
      if (local_a50[0] < 2) {
        if (local_a38 != 0) {
          FUN_1002b2f0(local_a38);
        }
        goto LAB_10016c4c;
      }
    }
    else {
      if (local_a50[0] == 6) {
        FUN_10056ae0(local_a4c,0xcd,0x10091d1a);
        FUN_10056ae0(local_a4c,0xce,0x10091d11);
        FUN_10056ae0(local_a4c,0xd5,0x10091d2b);
        goto LAB_10016fa0;
      }
      if (5 < local_a50[0]) goto LAB_10016fa0;
    }
    if (local_a50[0] == 3) {
      uVar1 = 0x10091cfd;
    }
    else {
      uVar1 = 0x10091d04;
    }
    FUN_10056ae0(local_a4c,0xcd,uVar1);
    FUN_10056ae0(local_a4c,0xce,0x10091d11);
    FUN_10056ae0(local_a4c,0xd5,0x10091d15);
    goto LAB_10016fa0;
  }
LAB_10016d98:
  FUN_1002c800(iVar2,&local_a48,&local_a44);
  FUN_100568b0(local_a4c,0xd5,&local_a48,4);
  if (local_a50[0] == 4) {
    local_a20 = 0xc;
    local_a1f[0] = local_a48;
    local_a1f[1] = 0x2028616c;
    local_a1f[2] = 0x69617329;
    FUN_10056ae0(local_a4c,0xcd,&local_a20);
  }
  else {
    if (local_a48 == 0x48546674) {
      iVar3 = 0x10091d5e;
    }
    else if (local_a48 < 0x48546674) {
      if (local_a48 == 0x4854626d) {
        iVar3 = 0x10091d6e;
      }
      else if ((local_a48 < 0x4854626d) && (local_a48 == 0x4150504c)) {
        iVar3 = 0x10091d30;
      }
      else {
LAB_10016ea0:
        iVar3 = 0;
      }
    }
    else if (local_a48 == 0x54455854) {
      iVar3 = 0x10091d54;
    }
    else {
      if ((0x54455853 < local_a48) || (local_a48 != 0x53495444)) goto LAB_10016ea0;
      iVar3 = 0x10091d44;
    }
    if (iVar3 == 0) {
      FUN_100568b0(local_a4c,0xcd,&local_a48,4);
    }
    else {
      FUN_10056ae0(local_a4c,0xcd);
    }
  }
  if (local_a44 == 0x53495421) {
    iVar3 = 0x10091d87;
  }
  else if (local_a44 < 0x53495421) {
    if ((local_a44 == 0x48544c53) || ((local_a44 < 0x48544c53 && (local_a44 == 0x48544c43)))) {
      iVar3 = 0x10091d7f;
    }
    else {
LAB_10016f44:
      iVar3 = 0;
    }
  }
  else {
    if (local_a44 != 0x74747874) goto LAB_10016f44;
    iVar3 = 0x10091d8f;
  }
  if (iVar3 == 0) {
    FUN_100568b0(local_a4c,0xce,&local_a44,4);
  }
  else {
    FUN_10056ae0(local_a4c,0xce);
  }
  uVar1 = FUN_1002c4d0(iVar2,0);
  FUN_10056a90(local_a4c,0xcf,uVar1);
LAB_10016fa0:
  FUN_1002bce0(local_a3c,&local_920,0);
  FUN_10056ae0(local_a4c,0xc9,&local_920);
  if (local_a50[0] != 6) {
    FUN_1002c910(iVar2,auStack_a28,auStack_a30);
    local_a20 = FUN_1002c740(iVar2,local_a1f,0xff,0);
    FUN_100568b0(local_a4c,0xd0,auStack_a30,8);
    FUN_100568b0(local_a4c,0xd1,auStack_a28,8);
    FUN_10056ae0(local_a4c,0xd2,&local_a20);
  }
  FUN_10058a70(param_3,local_a4c);
  if (local_a38 != 0) {
    FUN_1002b2f0(local_a38);
  }
  FUN_1002b2f0(local_a3c);
  if (local_a40 != 0) {
    FUN_1002b2f0(local_a40);
  }
  FUN_100563d0(local_a4c);
  return;
}

