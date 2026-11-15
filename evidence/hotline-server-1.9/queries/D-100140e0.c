
void FUN_100140e0(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  short sVar4;
  char cVar5;
  undefined1 auStack_920 [256];
  undefined1 auStack_820 [2056];
  
  FUN_10056c70(param_4,0xc9,auStack_920,0x100);
  uVar1 = FUN_10056b60(param_4,0xca,auStack_820,0x800);
  iVar2 = FUN_10007ee0(param_1,param_2);
  iVar3 = FUN_1002b0e0(iVar2,auStack_820,uVar1,auStack_920,2,0);
  if (iVar3 == 0) {
    FUN_1000ef30(param_3,0x100915c2,auStack_920);
    FUN_1002b2f0(0);
    if (iVar2 == 0) {
      return;
    }
    FUN_1002b2f0(iVar2);
    return;
  }
  sVar4 = FUN_1002c630(iVar3);
  if ((sVar4 == 3) || (sVar4 == 5)) {
    cVar5 = FUN_10008ab0(param_1,param_2,6);
    if (cVar5 == '\0') {
      uVar1 = FUN_10056380(0,0);
      FUN_10056ae0(uVar1,100,0x10091604);
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
    cVar5 = FUN_10008ab0(param_1,param_2,0);
    if (cVar5 == '\0') {
      uVar1 = FUN_10056380(0,0);
      FUN_10056ae0(uVar1,100,0x1009162b);
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
  FUN_1002ba20(iVar3);
  uVar1 = FUN_10056380(0,0);
  FUN_10058a70(param_3,uVar1);
  FUN_100563d0(uVar1);
  FUN_100068e0(param_1,param_2,0x10091665,auStack_920);
  FUN_1002b2f0(iVar3);
  if (iVar2 != 0) {
    FUN_1002b2f0(iVar2);
  }
  return;
}

