
void FUN_1000fc20(int param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  short sVar1;
  int iVar2;
  undefined4 uVar3;
  char cVar9;
  undefined1 uVar10;
  uint uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  uint uVar7;
  int iVar8;
  int iVar11;
  undefined4 *puVar12;
  int iVar13;
  undefined1 auStack_67 [71];
  
  iVar2 = FUN_10057d00();
  if (0x3c < (uint)(iVar2 - *(int *)(param_2 + 0xa4))) {
    *(int *)(param_2 + 0xa4) = iVar2;
    *(undefined2 *)(param_2 + 0x144) = 0;
  }
  if (*(ushort *)(param_2 + 0x144) < 0x2801) {
    uVar3 = FUN_10056380(0,0);
    cVar9 = FUN_10008a90(param_1,param_2,10);
    if (cVar9 == '\0') {
      FUN_10056a90(uVar3,0x6d,1);
      FUN_10056ae0(uVar3,0x65,0x100906fd);
      FUN_10058ca0(*(undefined4 *)(param_2 + 4),0x68,uVar3);
      FUN_100563d0(uVar3);
    }
    else {
      iVar2 = FUN_10056b90(param_4,0x6d);
      if (iVar2 == 1) {
        uVar10 = FUN_10054180(auStack_67,0x3f,0x10090729,param_2 + 0x38);
      }
      else {
        uVar10 = FUN_10054180(auStack_67,0x3f,0x10090734,param_2 + 0x38);
      }
      uVar4 = FUN_100567c0(param_4,0x65);
      if (0x2000 < uVar4) {
        uVar4 = 0x2000;
      }
      uVar5 = FUN_10052c50(uVar4,0);
      uVar6 = FUN_10053290(uVar5);
      FUN_10056b60(param_4,0x65,uVar6,uVar4);
      iVar2 = FUN_1006d220(uVar6,uVar4,0xffffffff);
      if (iVar2 == *(int *)(param_2 + 0x13c)) {
        sVar1 = *(short *)(param_2 + 0x140);
        *(short *)(param_2 + 0x140) = sVar1 + 1;
        if (sVar1 == 4) {
          FUN_100583b0(*(undefined4 *)(param_2 + 4));
          FUN_100063c0(param_1,*(undefined4 *)(param_2 + 0x10));
          FUN_100068e0(param_1,param_2,s_Autobanned_for_Chat_Spam_10090741);
          FUN_10053310(uVar5);
          FUN_100563d0(uVar3);
          return;
        }
      }
      else {
        *(int *)(param_2 + 0x13c) = iVar2;
        *(undefined2 *)(param_2 + 0x140) = 0;
      }
      FUN_10053310(uVar5);
      FUN_100534d0(uVar5,0,auStack_67,uVar10);
      FUN_1006cf70(uVar5,1,0x1009075a,1,auStack_67,uVar10);
      uVar6 = FUN_10053290(uVar5);
      uVar4 = FUN_10052f80(uVar5);
      if (0x2000 < uVar4) {
        uVar4 = 0x2000;
      }
      uVar7 = 0x5a;
      if (0x59 < uVar4) {
        uVar7 = uVar4;
      }
      *(short *)(param_2 + 0x144) = *(short *)(param_2 + 0x144) + (short)uVar7;
      FUN_100568b0(uVar3,0x65,uVar6,uVar4);
      FUN_10053310(uVar5);
      FUN_10052e90(uVar5);
      iVar2 = FUN_10056b90(param_4,0x72);
      if (iVar2 == 0) {
        for (puVar12 = *(undefined4 **)(param_1 + 0x34); puVar12 != (undefined4 *)0x0;
            puVar12 = (undefined4 *)*puVar12) {
          cVar9 = FUN_10058600(puVar12[1]);
          if ((cVar9 != '\0') && (cVar9 = FUN_10008a90(param_1,puVar12,9), cVar9 != '\0')) {
            FUN_10058ca0(puVar12[1],0x6a,uVar3);
          }
        }
      }
      else {
        iVar8 = FUN_10004760(param_1,iVar2);
        if (iVar8 != 0) {
          FUN_10056a90(uVar3,0x72,iVar2);
          iVar13 = *(int *)(iVar8 + 4);
          iVar2 = *(int *)(iVar8 + 8);
          for (iVar8 = 0; iVar8 != iVar2; iVar8 = iVar8 + 1) {
            iVar11 = *(int *)(iVar13 + iVar8 * 4);
            cVar9 = FUN_10058600(*(undefined4 *)(iVar11 + 4));
            if ((cVar9 != '\0') && (cVar9 = FUN_10008a90(param_1,iVar11,9), cVar9 != '\0')) {
              FUN_10058ca0(*(undefined4 *)(iVar11 + 4),0x6a,uVar3);
            }
          }
        }
      }
      FUN_100563d0(uVar3);
    }
  }
  else {
    FUN_100583b0(*(undefined4 *)(param_2 + 4));
    FUN_100063c0(param_1,*(undefined4 *)(param_2 + 0x10));
    FUN_100068e0(param_1,param_2,s_Autobanned_for_flooding_100905fd);
  }
  return;
}

