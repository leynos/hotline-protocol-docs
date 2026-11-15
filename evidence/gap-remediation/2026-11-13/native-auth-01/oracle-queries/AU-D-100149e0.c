
void FUN_100149e0(undefined4 param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  bool bVar1;
  undefined4 uVar2;
  uint uVar3;
  byte *pbVar4;
  byte local_60;
  byte local_5f [75];
  
  if ((*(byte *)(param_2 + 9) & 1) == 0) {
    uVar2 = FUN_10056380(0,0);
    FUN_10056ae0(uVar2,100,0x10091893);
    FUN_10058a10(param_3,1);
    FUN_10058a70(param_3,uVar2);
    FUN_100563d0(uVar2);
  }
  else {
    FUN_10056c70(param_4,0x69,&local_60,0x40);
    uVar3 = (uint)local_60;
    pbVar4 = local_5f;
    while (bVar1 = uVar3 != 0, uVar3 = uVar3 - 1, bVar1) {
      *pbVar4 = ~*pbVar4;
      pbVar4 = pbVar4 + 1;
    }
    FUN_100541e0(local_5f,local_60,0);
    FUN_10007340(param_1,&local_60);
    uVar2 = FUN_10056380(0,0);
    FUN_10058a70(param_3,uVar2);
    FUN_100563d0(uVar2);
    FUN_10005f90(param_1,&local_60,param_2);
    FUN_10006fe0(param_1,param_2,0x100918f5,&local_60);
    FUN_100068e0(param_1,param_2,0x100918fc,&local_60);
  }
  return;
}

