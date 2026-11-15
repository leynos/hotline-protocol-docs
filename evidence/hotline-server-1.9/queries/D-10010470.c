
void FUN_10010470(undefined4 param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  char cVar7;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  undefined1 auStack_828 [2064];
  
  uVar1 = FUN_10056b60(param_4,0x145,auStack_828,0x800);
  cVar7 = FUN_10008ad0(param_1,param_2,0x15);
  if (cVar7 == '\0') {
    uVar1 = FUN_10056380(0,0);
    FUN_10056ae0(uVar1,100,0x100907f1);
    FUN_10058a10(param_3,1);
    FUN_10058a70(param_3,uVar1);
    FUN_100563d0(uVar1);
  }
  else {
    iVar2 = FUN_10007f40(param_1,param_2);
    iVar3 = FUN_1002b0e0(iVar2,auStack_828,uVar1,0,0x20a,0);
    if (iVar3 == 0) {
      uVar1 = FUN_10056380(0,0);
      FUN_10056ae0(uVar1,100,0x10090817);
      FUN_10058a10(param_3,1);
      FUN_10058a70(param_3,uVar1);
      FUN_100563d0(uVar1);
      FUN_1002b2f0(0);
      if (iVar2 != 0) {
        FUN_1002b2f0(iVar2);
      }
    }
    else {
      uVar1 = FUN_10056b90(param_4,0x146);
      FUN_10056c70(param_4,0x148,auStack_828,0x20);
      uVar4 = FUN_10056b90(param_4,0x14e);
      iVar5 = FUN_100229b0(iVar3,uVar1,auStack_828,param_2 + 0x38,uVar4,0,0);
      if (iVar5 == 0) {
        uVar1 = FUN_10056380(0,0);
        FUN_10056ae0(uVar1,100,0x1009085e);
        FUN_10058a10(param_3,1);
        FUN_10058a70(param_3,uVar1);
        FUN_100563d0(uVar1);
        FUN_1002b2f0(iVar3);
        if (iVar2 != 0) {
          FUN_1002b2f0(iVar2);
        }
      }
      else {
        FUN_10056cb0(param_4,0x147,auStack_828,0x20);
        iVar6 = FUN_100567c0(param_4,0x14d);
        if (iVar6 == 0) {
          uVar1 = FUN_10056380(0,0);
          FUN_10056ae0(uVar1,100,0x1009085e);
          FUN_10058a10(param_3,1);
          FUN_10058a70(param_3,uVar1);
          FUN_100563d0(uVar1);
          FUN_1002b2f0(iVar3);
          if (iVar2 != 0) {
            FUN_1002b2f0(iVar2);
          }
        }
        else {
          uVar1 = FUN_10052a10(iVar6);
          FUN_10056b60(param_4,0x14d,uVar1,iVar6);
          cVar7 = FUN_10022ea0(iVar3,iVar5,auStack_828,uVar1,iVar6);
          if (cVar7 == '\0') {
            uVar4 = FUN_10056380(0,0);
            FUN_10056ae0(uVar4,100,0x10090896);
            FUN_10058a10(param_3,1);
            FUN_10058a70(param_3,uVar4);
            FUN_100563d0(uVar4);
            FUN_10052c10(uVar1);
            FUN_1002b2f0(iVar3);
            if (iVar2 != 0) {
              FUN_1002b2f0(iVar2);
            }
          }
          else {
            uVar4 = FUN_10056380(0,0);
            FUN_10058a70(param_3,uVar4);
            FUN_100563d0(uVar4);
            FUN_10052c10(uVar1);
            FUN_1002b2f0(iVar3);
            if (iVar2 != 0) {
              FUN_1002b2f0(iVar2);
            }
          }
        }
      }
    }
  }
  return;
}

