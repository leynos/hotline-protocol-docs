
void FUN_10004f30(undefined4 param_1,int param_2)

{
  undefined4 uVar1;
  undefined2 uVar2;
  
  if (param_2 != 0) {
    uVar1 = FUN_10056380(0,0);
    FUN_10056a90(uVar1,0x67,*(undefined2 *)(param_2 + 0x14));
    FUN_10056a90(uVar1,0x68,(int)*(short *)(param_2 + 0x16));
    uVar2 = FUN_10005000(param_1,param_2);
    FUN_10056a90(uVar1,0x70,uVar2);
    FUN_10056ae0(uVar1,0x66,param_2 + 0x38);
    FUN_10005510(param_1,0x12d,uVar1);
    FUN_100563d0(uVar1);
  }
  return;
}

