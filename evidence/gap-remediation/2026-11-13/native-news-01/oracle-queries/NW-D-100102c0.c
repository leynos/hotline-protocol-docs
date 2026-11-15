
void FUN_100102c0(undefined4 param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  undefined4 uVar5;
  undefined1 auStack_820 [2060];
  
  uVar1 = FUN_10056380(0,0);
  iVar2 = FUN_10007f40(param_1,param_2);
  uVar3 = FUN_10056b60(param_4,0x145,auStack_820,0x800);
  if (uVar3 < 6) {
    FUN_10005710(param_1,iVar2,uVar1,*(undefined4 *)(param_2 + 0x138));
  }
  else {
    iVar4 = FUN_1002b0e0(iVar2,auStack_820,uVar3,0,0x212,0);
    if (iVar4 == 0) {
      uVar5 = FUN_10056380(0,0);
      FUN_10056ae0(uVar5,100,0x100907ab);
      FUN_10058a10(param_3,1);
      FUN_10058a70(param_3,uVar5);
      FUN_100563d0(uVar5);
      FUN_1002b2f0(0);
      if (iVar2 != 0) {
        FUN_1002b2f0(iVar2);
      }
      FUN_100563d0(uVar1);
      return;
    }
    FUN_10005710(param_1,iVar4,uVar1,*(undefined4 *)(param_2 + 0x138));
    FUN_1002b2f0(iVar4);
  }
  FUN_10058a70(param_3,uVar1);
  if (iVar2 != 0) {
    FUN_1002b2f0(iVar2);
  }
  FUN_100563d0(uVar1);
  return;
}

