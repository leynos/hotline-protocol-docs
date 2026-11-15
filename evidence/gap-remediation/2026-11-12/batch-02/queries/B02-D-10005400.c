
void FUN_10005400(undefined4 param_1,int param_2,uint param_3)

{
  undefined4 uVar1;
  undefined2 uVar2;
  
  if ((param_2 != 0) && ((*(byte *)(param_2 + 0x14a) >> 6 & 1) != -(param_3 & 0xff) >> 0x1f)) {
    uVar1 = FUN_10056380(0,0);
    *(byte *)(param_2 + 0x14a) =
         (byte)((-(param_3 & 0xff) >> 0x1f) << 6) | *(byte *)(param_2 + 0x14a) & 0xbf;
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

