
void FUN_100108a0(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  char cVar5;
  int iVar2;
  int iVar3;
  uint uVar4;
  undefined1 auStack_820 [2052];
  
  uVar1 = FUN_10056b60(param_4,0x145,auStack_820,0x800);
  cVar5 = FUN_10008ad0(param_1,param_2,0x21);
  if (cVar5 == '\0') {
    uVar1 = FUN_10056380(0,0);
    FUN_10056ae0(uVar1,100,0x100908d6);
    FUN_10058a10(param_3,1);
    FUN_10058a70(param_3,uVar1);
    FUN_100563d0(uVar1);
  }
  else {
    iVar2 = FUN_10007f40(param_1,param_2);
    iVar3 = FUN_1002b0e0(iVar2,auStack_820,uVar1,0,0x20a,0);
    if (iVar3 == 0) {
      uVar1 = FUN_10056380(0,0);
      FUN_10056ae0(uVar1,100,0x100908fe);
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
      uVar4 = FUN_10056b90(param_4,0x151);
      cVar5 = FUN_10023830(iVar3,uVar1,(-uVar4 | uVar4) >> 0x1f);
      if (cVar5 == '\0') {
        FUN_10027c30(1,0xc);
      }
      uVar1 = FUN_10056380(0,0);
      FUN_10058a70(param_3,uVar1);
      FUN_100563d0(uVar1);
      FUN_1002b2f0(iVar3);
      if (iVar2 != 0) {
        FUN_1002b2f0(iVar2);
      }
    }
  }
  return;
}

