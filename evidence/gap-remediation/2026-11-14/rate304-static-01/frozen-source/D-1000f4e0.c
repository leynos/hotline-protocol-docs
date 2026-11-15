
void FUN_1000f4e0(undefined4 param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  short sVar1;
  undefined2 uVar6;
  short sVar7;
  int iVar2;
  int iVar3;
  int iVar4;
  char cVar8;
  undefined4 uVar5;
  int iVar9;
  undefined1 auStack_20b0 [128];
  undefined1 auStack_2030 [4096];
  undefined1 auStack_1030 [4108];
  
  uVar6 = FUN_10056b90(param_4,0x67);
  sVar7 = FUN_10056b90(param_4,0x71);
  iVar2 = FUN_10056b60(param_4,0x65,auStack_2030,0x1000);
  iVar3 = FUN_100567c0(param_4,0xd6);
  if (iVar3 != 0) {
    FUN_10056b60(param_4,0xd6,auStack_1030,0x1000);
  }
  iVar4 = FUN_10057d00();
  if (0x3c < (uint)(iVar4 - *(int *)(param_2 + 0xa0))) {
    *(int *)(param_2 + 0xa0) = iVar4;
    *(undefined2 *)(param_2 + 0x142) = 0;
  }
  iVar4 = FUN_1006d220(auStack_2030,iVar2,0xffffffff);
  if (iVar4 == *(int *)(param_2 + 0x13c)) {
    sVar1 = *(short *)(param_2 + 0x140);
    *(short *)(param_2 + 0x140) = sVar1 + 1;
    if (sVar1 == 4) {
      FUN_100583b0(*(undefined4 *)(param_2 + 4));
      FUN_100063c0(param_1,*(undefined4 *)(param_2 + 0x10));
      FUN_100068e0(param_1,param_2,s_Autobanned_for_Message_Spam_100905e1);
      return;
    }
  }
  else {
    *(int *)(param_2 + 0x13c) = iVar4;
    *(undefined2 *)(param_2 + 0x140) = 0;
  }
  if (*(ushort *)(param_2 + 0x142) < 0x15) {
    *(short *)(param_2 + 0x142) = *(short *)(param_2 + 0x142) + 1;
    cVar8 = FUN_10008a90(param_1,param_2,0x28);
    if (cVar8 == '\0') {
      uVar5 = FUN_10056380(0,0);
      FUN_10056ae0(uVar5,100,s__You_are_not_allowed_to_send_pri_10090615);
      FUN_10058a10(param_3,1);
      FUN_10058a70(param_3,uVar5);
      FUN_100563d0(uVar5);
    }
    else {
      iVar4 = FUN_10004730(param_1,uVar6);
      if ((iVar4 == 0) || (cVar8 = FUN_10058600(*(undefined4 *)(iVar4 + 4)), cVar8 == '\0')) {
        uVar5 = FUN_10056380(0,0);
        FUN_10056ae0(uVar5,100,s__You_are_not_allowed_to_send_pri_10090615 + 0x2e);
        FUN_10058a10(param_3,1);
        FUN_10058a70(param_3,uVar5);
        FUN_100563d0(uVar5);
      }
      else {
        uVar5 = FUN_10056380(0,0);
        FUN_10058a70(param_3,uVar5);
        if ((*(char *)(param_2 + 0xb0) == '\0') &&
           (((*(char *)(iVar4 + 0xb2) != '\0' || (*(char *)(iVar4 + 0xb0) != '\0')) && (sVar7 == 1))
           )) {
          FUN_10056a90(uVar5,0x67,*(undefined2 *)(iVar4 + 0x14));
          FUN_10056ae0(uVar5,0x66,iVar4 + 0x38);
          iVar9 = 0;
          if (*(char *)(iVar4 + 0xb2) == '\0') {
            if (*(char *)(iVar4 + 0xb0) != '\0') {
              FUN_10056a90(uVar5,0x71,2);
              iVar9 = FUN_10054180(auStack_20b0,0x80,
                                   s__You_are_not_allowed_to_send_pri_10090615 + 0x7d,iVar4 + 0x38);
            }
          }
          else {
            FUN_10056a90(uVar5,0x71,4);
            iVar9 = FUN_100539c0(auStack_20b0,iVar4 + 0xb4,*(undefined1 *)(iVar4 + 0xb3));
          }
          if (iVar9 != 0) {
            FUN_100568b0(uVar5,0x65,auStack_20b0);
            FUN_10058ca0(*(undefined4 *)(param_2 + 4),0x68,uVar5);
          }
        }
        if (*(char *)(iVar4 + 0xb0) == '\0') {
          if (sVar7 == 2) {
            iVar2 = FUN_10054180(auStack_2030,0x1000,
                                 s__You_are_not_allowed_to_send_pri_10090615 + 0x7d,param_2 + 0x38);
          }
          if (sVar7 == 3) {
            iVar2 = FUN_10054180(auStack_2030,0x1000,s___s_does_not_accept_private_chat_100906b8,
                                 param_2 + 0x38);
          }
          if (iVar2 != 0) {
            FUN_10056820(uVar5);
            FUN_10056a90(uVar5,0x67,*(undefined2 *)(param_2 + 0x14));
            FUN_10056ae0(uVar5,0x66,param_2 + 0x38);
            FUN_10056a90(uVar5,0x71,sVar7);
            FUN_100568b0(uVar5,0x65,auStack_2030,iVar2);
            if (iVar3 != 0) {
              FUN_100568b0(uVar5,0xd6,auStack_1030,iVar3);
            }
            FUN_10058ca0(*(undefined4 *)(iVar4 + 4),0x68,uVar5);
          }
        }
        FUN_100563d0(uVar5);
      }
    }
  }
  else {
    FUN_100583b0(*(undefined4 *)(param_2 + 4));
    FUN_100063c0(param_1,*(undefined4 *)(param_2 + 0x10));
    FUN_100068e0(param_1,param_2,s_Autobanned_for_flooding_100905fd);
  }
  return;
}

