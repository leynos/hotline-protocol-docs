
void FUN_1000f990(int param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  short sVar1;
  char cVar5;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  undefined4 *puVar6;
  undefined1 auStack_1028 [4116];
  
  cVar5 = FUN_10008a90(param_1,param_2,0x20);
  if (cVar5 == '\0') {
    uVar2 = FUN_10056380(0,0);
    FUN_10056ae0(uVar2,100,0x100906db);
    FUN_10058a10(param_3,1);
    FUN_10058a70(param_3,uVar2);
    FUN_100563d0(uVar2);
  }
  else {
    uVar2 = FUN_10056380(0,0);
    FUN_10058a70(param_3,uVar2);
    iVar3 = FUN_10056b60(param_4,0x65,auStack_1028,0x1000);
    iVar4 = FUN_10057d00();
    if (0x3c < (uint)(iVar4 - *(int *)(param_2 + 0xa0))) {
      *(int *)(param_2 + 0xa0) = iVar4;
      *(undefined2 *)(param_2 + 0x142) = 0;
    }
    iVar4 = FUN_1006d220(auStack_1028,iVar3,0xffffffff);
    if (iVar4 == *(int *)(param_2 + 0x13c)) {
      sVar1 = *(short *)(param_2 + 0x140);
      *(short *)(param_2 + 0x140) = sVar1 + 1;
      if (sVar1 == 4) {
        FUN_100583b0(*(undefined4 *)(param_2 + 4));
        FUN_100063c0(param_1,*(undefined4 *)(param_2 + 0x10));
        FUN_100068e0(param_1,param_2,s_Autobanned_for_Message_Spam_100905e1);
        FUN_100563d0(uVar2);
        return;
      }
    }
    else {
      *(int *)(param_2 + 0x13c) = iVar4;
      *(undefined2 *)(param_2 + 0x140) = 0;
    }
    if (*(ushort *)(param_2 + 0x142) < 0x15) {
      *(short *)(param_2 + 0x142) = *(short *)(param_2 + 0x142) + 1;
      if (iVar3 != 0) {
        FUN_10056a90(uVar2,0x67,*(undefined2 *)(param_2 + 0x14));
        FUN_10056ae0(uVar2,0x66,param_2 + 0x38);
        FUN_100568b0(uVar2,0x65,auStack_1028,iVar3);
        for (puVar6 = *(undefined4 **)(param_1 + 0x34); puVar6 != (undefined4 *)0x0;
            puVar6 = (undefined4 *)*puVar6) {
          if (((*(short *)(puVar6 + 5) != *(short *)(param_2 + 0x14)) &&
              (cVar5 = FUN_10058600(puVar6[1]), cVar5 != '\0')) &&
             (*(char *)((int)puVar6 + 0x14a) < '\0')) {
            FUN_10058ca0(puVar6[1],0x163,uVar2);
          }
        }
      }
      FUN_100563d0(uVar2);
    }
    else {
      FUN_100583b0(*(undefined4 *)(param_2 + 4));
      FUN_100063c0(param_1,*(undefined4 *)(param_2 + 0x10));
      FUN_100068e0(param_1,param_2,s_Autobanned_for_flooding_100905fd);
      FUN_100563d0(uVar2);
    }
  }
  return;
}

