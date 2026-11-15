
void FUN_1000f130(int param_1,undefined4 param_2,undefined4 param_3)

{
  char cVar5;
  undefined4 uVar1;
  undefined4 uVar2;
  uint uVar3;
  undefined4 uVar4;
  
  cVar5 = FUN_10008a90(param_1,param_2,0x14);
  if (cVar5 == '\0') {
    uVar1 = FUN_10056380(0,0);
    FUN_10056ae0(uVar1,100,s_8You_are_not_allowed_to_read_new_10090520);
    FUN_10058a10(param_3,1);
    FUN_10058a70(param_3,uVar1);
    FUN_100563d0(uVar1);
  }
  else {
    uVar1 = *(undefined4 *)(param_1 + 4);
    uVar2 = FUN_10053290();
    uVar3 = FUN_10052f80(*(undefined4 *)(param_1 + 4));
    if (0xffff < uVar3) {
      uVar3 = 0xffff;
    }
    uVar4 = FUN_10056380(0,0);
    FUN_100568b0(uVar4,0x65,uVar2,uVar3);
    FUN_10058a70(param_3,uVar4);
    FUN_100563d0(uVar4);
    FUN_10053310(uVar1);
  }
  return;
}

