
void FUN_10011370(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  char cVar5;
  undefined1 auStack_828 [2068];
  
  uVar1 = FUN_10056380(0,0);
  iVar2 = FUN_10007f40(param_1,param_2);
  uVar3 = FUN_10056b60(param_4,0x145,auStack_828,0x800);
  iVar4 = FUN_1002b0e0(iVar2,auStack_828,uVar3,0,0x20a,0);
  if (iVar4 == 0) {
    uVar3 = FUN_10056380(0,0);
    FUN_10056ae0(uVar3,100,0x10090c6d);
    FUN_10058a10(param_3,1);
    FUN_10058a70(param_3,uVar3);
    FUN_100563d0(uVar3);
    FUN_1002b2f0(0);
    if (iVar2 != 0) {
      FUN_1002b2f0(iVar2);
    }
    FUN_100563d0(uVar1);
  }
  else {
    cVar5 = FUN_100059e0(param_1,iVar4,uVar1);
    if (cVar5 == '\0') {
      uVar3 = FUN_10056380(0,0);
      FUN_10056ae0(uVar3,100,0x10090cb8);
      FUN_10058a10(param_3,1);
      FUN_10058a70(param_3,uVar3);
      FUN_100563d0(uVar3);
      FUN_1002b2f0(iVar4);
      if (iVar2 != 0) {
        FUN_1002b2f0(iVar2);
      }
      FUN_100563d0(uVar1);
    }
    else {
      FUN_10058a70(param_3,uVar1);
      FUN_1002b2f0(iVar4);
      if (iVar2 != 0) {
        FUN_1002b2f0(iVar2);
      }
      FUN_100563d0(uVar1);
    }
  }
  return;
}

