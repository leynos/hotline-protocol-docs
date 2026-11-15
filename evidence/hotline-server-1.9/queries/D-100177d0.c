
void FUN_100177d0(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  short sVar5;
  char cVar6;
  int iVar4;
  undefined1 auStack_920 [256];
  undefined1 auStack_820 [2048];
  
  FUN_10056c70(param_4,0xc9,auStack_920,0x100);
  uVar1 = FUN_10056b60(param_4,0xca,auStack_820,0x800);
  iVar2 = FUN_10007ee0(param_1,param_2);
  iVar3 = FUN_1002b0e0(iVar2,auStack_820,uVar1,auStack_920,2,0);
  if (iVar3 == 0) {
    FUN_1000ef30(param_3,0x10091ec2,auStack_920);
    FUN_1002b2f0(0);
    if (iVar2 == 0) {
      return;
    }
    FUN_1002b2f0(iVar2);
    return;
  }
  sVar5 = FUN_1002c630(iVar3);
  if ((sVar5 == 3) || (sVar5 == 5)) {
    cVar6 = FUN_10008ab0(param_1,param_2,8);
    if (cVar6 == '\0') {
      uVar1 = FUN_10056380(0,0);
      FUN_10056ae0(uVar1,100,0x10091efb);
      FUN_10058a10(param_3,1);
      FUN_10058a70(param_3,uVar1);
      FUN_100563d0(uVar1);
      FUN_1002b2f0(iVar3);
      if (iVar2 == 0) {
        return;
      }
      FUN_1002b2f0(iVar2);
      return;
    }
  }
  else {
    cVar6 = FUN_10008ab0(param_1,param_2,4);
    if (cVar6 == '\0') {
      uVar1 = FUN_10056380(0,0);
      FUN_10056ae0(uVar1,100,0x10091f20);
      FUN_10058a10(param_3,1);
      FUN_10058a70(param_3,uVar1);
      FUN_100563d0(uVar1);
      FUN_1002b2f0(iVar3);
      if (iVar2 == 0) {
        return;
      }
      FUN_1002b2f0(iVar2);
      return;
    }
  }
  uVar1 = FUN_10056b60(param_4,0xd4,auStack_820,0x800);
  iVar4 = FUN_1002b0e0(iVar2,auStack_820,uVar1,0,0x212,0);
  if (iVar4 == 0) {
    FUN_1000ef30(param_3,0x10091f43,auStack_920);
    FUN_1002b2f0(0);
    FUN_1002b2f0(iVar3);
    if (iVar2 != 0) {
      FUN_1002b2f0(iVar2);
    }
  }
  else {
    FUN_1002c130(iVar3,iVar4);
    uVar1 = FUN_10056380(0,0);
    FUN_10058a70(param_3,uVar1);
    FUN_100563d0(uVar1);
    FUN_100068e0(param_1,param_2,0x1009206a,auStack_920);
    FUN_1002b2f0(iVar4);
    FUN_1002b2f0(iVar3);
    if (iVar2 != 0) {
      FUN_1002b2f0(iVar2);
    }
  }
  return;
}

