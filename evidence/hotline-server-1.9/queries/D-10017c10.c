
void FUN_10017c10(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  char cVar5;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined1 auStack_920 [256];
  undefined1 auStack_820 [2048];
  
  FUN_10056c70(param_4,0xc9,auStack_920,0x100);
  uVar1 = FUN_10056b60(param_4,0xca,auStack_820,0x800);
  cVar5 = FUN_10008ab0(param_1,param_2,0x1f);
  if (cVar5 == '\0') {
    uVar1 = FUN_10056380(0,0);
    FUN_10056ae0(uVar1,100,0x10092075);
    FUN_10058a10(param_3,1);
    FUN_10058a70(param_3,uVar1);
    FUN_100563d0(uVar1);
  }
  else {
    iVar2 = FUN_10007ee0(param_1,param_2);
    iVar3 = FUN_1002b0e0(iVar2,auStack_820,uVar1,auStack_920,2,0);
    if (iVar3 == 0) {
      FUN_1000ef30(param_3,0x1009209a,auStack_920);
      FUN_1002b2f0(0);
      if (iVar2 != 0) {
        FUN_1002b2f0(iVar2);
      }
    }
    else {
      uVar1 = FUN_10056b60(param_4,0xd4,auStack_820,0x800);
      iVar4 = FUN_1002b0e0(iVar2,auStack_820,uVar1,auStack_920,1,0);
      if (iVar4 == 0) {
        FUN_1000ef30(param_3,0x100920d9,auStack_920);
        FUN_1002b2f0(0);
        FUN_1002b2f0(iVar3);
        if (iVar2 != 0) {
          FUN_1002b2f0(iVar2);
        }
      }
      else {
        FUN_1002b6f0(iVar4,iVar3);
        uVar1 = FUN_10056380(0,0);
        FUN_10058a70(param_3,uVar1);
        FUN_100563d0(uVar1);
        FUN_100068e0(param_1,param_2,0x100921b3,auStack_920);
        FUN_1002b2f0(iVar4);
        FUN_1002b2f0(iVar3);
        if (iVar2 != 0) {
          FUN_1002b2f0(iVar2);
        }
      }
    }
  }
  return;
}

