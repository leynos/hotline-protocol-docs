
void FUN_10011ee0(int param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined1 auStack_308 [752];
  
  uVar1 = FUN_10056380(0,0);
  FUN_1006cd50(auStack_308,0x2de);
  FUN_100073c0(param_1,param_2 + 0x78,auStack_308);
  uVar2 = FUN_10056380(0,0);
  FUN_10058a70(param_3,uVar2);
  FUN_100563d0(uVar2);
  FUN_10004d50(param_1,param_2,param_4,auStack_308);
  *(byte *)(param_2 + 0x14a) = *(byte *)(param_2 + 0x14a) & 0x7f | 0x80;
  FUN_100068e0(param_1,param_2,s_Login_successful_10090dcf);
  FUN_10056820(uVar1);
  FUN_100568b0(uVar1,0x6e,param_2 + 8,8);
  FUN_10058ca0(*(undefined4 *)(param_2 + 4),0x162,uVar1);
  FUN_10006e80(param_1,param_2);
  if ((*(uint *)(param_2 + 0x138) < 0x97) || (*(int *)(param_1 + 0x10) == 0)) {
    FUN_100563d0(uVar1);
  }
  else {
    FUN_10056820(uVar1);
    FUN_100568b0(uVar1,0x98,param_1 + 0x10,4);
    if (*(int *)(param_1 + 0x10) == 0x55524c20) {
      if (*(int *)(param_1 + 0x14) == 0) {
        FUN_100563d0(uVar1);
        return;
      }
      uVar2 = *(undefined4 *)(param_1 + 0x14);
      uVar3 = FUN_10053290();
      uVar4 = FUN_10052f80(*(undefined4 *)(param_1 + 0x14));
      FUN_100568b0(uVar1,0x99,uVar3,uVar4);
      FUN_10053310(uVar2);
    }
    else {
      if (*(int *)(param_1 + 0xc) == 0) {
        FUN_100563d0(uVar1);
        return;
      }
      if (*(int *)(param_1 + 0x14) != 0) {
        uVar2 = *(undefined4 *)(param_1 + 0x14);
        uVar3 = FUN_10053290();
        uVar4 = FUN_10052f80(*(undefined4 *)(param_1 + 0x14));
        FUN_100568b0(uVar1,0x99,uVar3,uVar4);
        FUN_10053310(uVar2);
      }
    }
    FUN_10058ca0(*(undefined4 *)(param_2 + 4),0x7a,uVar1);
    FUN_100563d0(uVar1);
  }
  return;
}

