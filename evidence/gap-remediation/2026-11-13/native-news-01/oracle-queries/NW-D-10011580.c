
void FUN_10011580(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  undefined4 uVar2;
  char cVar5;
  int iVar3;
  int iVar4;
  undefined1 auStack_820 [2052];
  
  uVar1 = FUN_10056380(0,0);
  uVar2 = FUN_10056b60(param_4,0x145,auStack_820,0x800);
  cVar5 = FUN_10008ad0(param_1,param_2,0x14);
  if (cVar5 == '\0') {
    uVar2 = FUN_10056380(0,0);
    FUN_10056ae0(uVar2,100,0x10090cf8);
    FUN_10058a10(param_3,1);
    FUN_10058a70(param_3,uVar2);
    FUN_100563d0(uVar2);
    FUN_100563d0(uVar1);
  }
  else {
    iVar3 = FUN_10007f40(param_1,param_2);
    iVar4 = FUN_1002b0e0(iVar3,auStack_820,uVar2,0,0x20a,0);
    if (iVar4 == 0) {
      uVar2 = FUN_10056380(0,0);
      FUN_10056ae0(uVar2,100,0x10090d1e);
      FUN_10058a10(param_3,1);
      FUN_10058a70(param_3,uVar2);
      FUN_100563d0(uVar2);
      FUN_1002b2f0(0);
      if (iVar3 != 0) {
        FUN_1002b2f0(iVar3);
      }
      FUN_100563d0(uVar1);
    }
    else {
      uVar2 = FUN_10056b90(param_4,0x146);
      FUN_10056cb0(param_4,0x147,auStack_820,0x100);
      cVar5 = FUN_10005ac0(param_1,iVar4,uVar2,auStack_820,uVar1);
      if (cVar5 == '\0') {
        FUN_10027c30(1,0xc);
      }
      FUN_10058a70(param_3,uVar1);
      FUN_1002b2f0(iVar4);
      if (iVar3 != 0) {
        FUN_1002b2f0(iVar3);
      }
      FUN_100563d0(uVar1);
    }
  }
  return;
}

