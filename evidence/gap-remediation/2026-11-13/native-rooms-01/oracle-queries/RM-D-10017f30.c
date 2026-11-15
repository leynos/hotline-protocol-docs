
void FUN_10017f30(int param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  int iVar1;
  char cVar8;
  undefined4 uVar2;
  uint uVar3;
  short sVar6;
  int iVar4;
  undefined4 uVar5;
  undefined2 uVar7;
  int iVar9;
  uint uVar10;
  undefined1 auStack_b0 [140];
  
  iVar1 = FUN_10057d00();
  if (0x3c < (uint)(iVar1 - *(int *)(param_2 + 0xa0))) {
    *(int *)(param_2 + 0xa0) = iVar1;
    *(undefined2 *)(param_2 + 0x142) = 0;
  }
  if (*(ushort *)(param_2 + 0x142) < 0x15) {
    *(short *)(param_2 + 0x142) = *(short *)(param_2 + 0x142) + 1;
    cVar8 = FUN_10008a90(param_1,param_2,0xb);
    if (cVar8 == '\0') {
      uVar2 = FUN_10056380(0,0);
      FUN_10056ae0(uVar2,100,s__You_are_not_allowed_to_create_a_100921bf);
      FUN_10058a10(param_3,1);
      FUN_10058a70(param_3,uVar2);
      FUN_100563d0(uVar2);
    }
    else {
      iVar1 = FUN_10052b70(0x18);
      uVar2 = FUN_100067d0(param_1);
      *(undefined4 *)(iVar1 + 0x10) = uVar2;
      FUN_10055a60(param_1 + 0x420,iVar1);
      FUN_100554e0(iVar1 + 4,param_2);
      uVar2 = FUN_10056380(0,0);
      FUN_10056a90(uVar2,0x72,*(undefined4 *)(iVar1 + 0x10));
      FUN_10056a90(uVar2,0x67,*(undefined2 *)(param_2 + 0x14));
      FUN_10056ae0(uVar2,0x66,param_2 + 0x38);
      uVar3 = FUN_10056550(param_4);
      for (uVar10 = 1; (uVar10 & 0xffff) <= (uVar3 & 0xffff); uVar10 = uVar10 + 1) {
        sVar6 = FUN_10056430(param_4,uVar10);
        if (sVar6 == 0x67) {
          uVar7 = FUN_10056c00(param_4,uVar10);
          iVar4 = FUN_10004730(param_1,uVar7);
          if (((iVar4 != 0) && (cVar8 = FUN_10058600(*(undefined4 *)(iVar4 + 4)), cVar8 != '\0')) &&
             (iVar4 != param_2)) {
            if ((*(char *)(param_2 + 0xb0) == '\0') &&
               ((*(char *)(iVar4 + 0xb2) != '\0' || (*(char *)(iVar4 + 0xb1) != '\0')))) {
              uVar5 = FUN_10056380(0,0);
              FUN_10056a90(uVar5,0x67,*(undefined2 *)(iVar4 + 0x14));
              FUN_10056ae0(uVar5,0x66,iVar4 + 0x38);
              iVar9 = 0;
              if (*(char *)(iVar4 + 0xb2) == '\0') {
                if (*(char *)(iVar4 + 0xb1) != '\0') {
                  FUN_10056a90(uVar5,0x71,3);
                  iVar9 = FUN_10054180(auStack_b0,0x80,s___s_does_not_accept_private_chat_100906b8,
                                       iVar4 + 0x38);
                }
              }
              else {
                FUN_10056a90(uVar5,0x71,4);
                iVar9 = FUN_100539c0(auStack_b0,iVar4 + 0xb4,*(undefined1 *)(iVar4 + 0xb3));
              }
              if (iVar9 != 0) {
                FUN_100568b0(uVar5,0x65,auStack_b0);
                FUN_10058ca0(*(undefined4 *)(param_2 + 4),0x68,uVar5);
              }
              FUN_100563d0(uVar5);
            }
            if (*(char *)(iVar4 + 0xb1) == '\0') {
              FUN_10058ca0(*(undefined4 *)(iVar4 + 4),0x71,uVar2);
            }
          }
        }
      }
      FUN_10056820(uVar2);
      FUN_10056a90(uVar2,0x72,*(undefined4 *)(iVar1 + 0x10));
      FUN_10056a90(uVar2,0x67,*(undefined2 *)(param_2 + 0x14));
      FUN_10056a90(uVar2,0x68,(int)*(short *)(param_2 + 0x16));
      uVar7 = FUN_10005000(param_1,param_2);
      FUN_10056a90(uVar2,0x70,uVar7);
      FUN_10056ae0(uVar2,0x66,param_2 + 0x38);
      FUN_10058a70(param_3,uVar2);
      FUN_100563d0(uVar2);
    }
  }
  else {
    FUN_100583b0(*(undefined4 *)(param_2 + 4));
    FUN_100063c0(param_1,*(undefined4 *)(param_2 + 0x10));
    FUN_100068e0(param_1,param_2,s_Autobanned_for_flooding_100905fd);
  }
  return;
}

