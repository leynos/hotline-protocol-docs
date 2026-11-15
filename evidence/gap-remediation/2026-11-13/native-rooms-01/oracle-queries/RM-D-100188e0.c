
void FUN_100188e0(undefined4 param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 uVar3;
  uint uVar4;
  short sVar7;
  undefined2 uVar8;
  int iVar5;
  char cVar9;
  int iVar6;
  uint uVar10;
  undefined1 auStack_a8 [136];
  
  uVar1 = FUN_10056380(0,0);
  iVar2 = FUN_10057d00();
  if (0x3c < (uint)(iVar2 - *(int *)(param_2 + 0xa0))) {
    *(int *)(param_2 + 0xa0) = iVar2;
    *(undefined2 *)(param_2 + 0x142) = 0;
  }
  if (*(ushort *)(param_2 + 0x142) < 0x15) {
    *(short *)(param_2 + 0x142) = *(short *)(param_2 + 0x142) + 1;
    uVar3 = FUN_10056b90(param_4,0x72);
    iVar2 = FUN_10004760(param_1,uVar3);
    if (iVar2 == 0) {
      FUN_100563d0(uVar1);
    }
    else {
      FUN_10056a90(uVar1,0x72,uVar3);
      FUN_10056a90(uVar1,0x67,*(undefined2 *)(param_2 + 0x14));
      FUN_10056ae0(uVar1,0x66,param_2 + 0x38);
      uVar4 = FUN_10056550(param_4);
      for (uVar10 = 1; uVar10 <= (uVar4 & 0xffff); uVar10 = uVar10 + 1) {
        sVar7 = FUN_10056430(param_4,uVar10 & 0xffff);
        if (sVar7 == 0x67) {
          uVar8 = FUN_10056c00(param_4,uVar10 & 0xffff);
          iVar5 = FUN_10004730(param_1,uVar8);
          if ((((iVar5 != 0) && (cVar9 = FUN_10058600(*(undefined4 *)(iVar5 + 4)), cVar9 != '\0'))
              && (iVar5 != param_2)) &&
             (iVar6 = FUN_1006cf30(iVar5,*(undefined4 *)(iVar2 + 4),*(undefined4 *)(iVar2 + 8)),
             iVar6 == 0)) {
            if ((*(char *)(param_2 + 0xb0) == '\0') &&
               ((*(char *)(iVar5 + 0xb2) != '\0' || (*(char *)(iVar5 + 0xb1) != '\0')))) {
              uVar3 = FUN_10056380(0,0);
              FUN_10056a90(uVar3,0x67,*(undefined2 *)(iVar5 + 0x14));
              FUN_10056ae0(uVar3,0x66,iVar5 + 0x38);
              iVar6 = 0;
              if (*(char *)(iVar5 + 0xb2) == '\0') {
                if (*(char *)(iVar5 + 0xb1) != '\0') {
                  FUN_10056a90(uVar3,0x71,3);
                  iVar6 = FUN_10054180(auStack_a8,0x80,s___s_does_not_accept_private_chat_100906b8,
                                       iVar5 + 0x38);
                }
              }
              else {
                FUN_10056a90(uVar3,0x71,4);
                iVar6 = FUN_100539c0(auStack_a8,iVar5 + 0xb4,*(undefined1 *)(iVar5 + 0xb3));
              }
              if (iVar6 != 0) {
                FUN_100568b0(uVar3,0x65,auStack_a8);
                FUN_10058ca0(*(undefined4 *)(param_2 + 4),0x68,uVar3);
              }
              FUN_100563d0(uVar3);
            }
            if (*(char *)(iVar5 + 0xb1) == '\0') {
              FUN_10058ca0(*(undefined4 *)(iVar5 + 4),0x71,uVar1);
            }
          }
        }
      }
      FUN_100563d0(uVar1);
    }
  }
  else {
    FUN_100583b0(*(undefined4 *)(param_2 + 4));
    FUN_100063c0(param_1,*(undefined4 *)(param_2 + 0x10));
    FUN_100068e0(param_1,param_2,s_Autobanned_for_flooding_100905fd);
    FUN_100563d0(uVar1);
  }
  return;
}

