
void FUN_10014bc0(undefined4 param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  bool bVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  uint uVar4;
  byte *pbVar5;
  byte local_340;
  byte local_33f [63];
  undefined1 auStack_300 [4];
  undefined1 auStack_2fc [524];
  undefined2 local_f0;
  undefined1 auStack_ee [170];
  short local_44;
  undefined1 local_42 [42];
  
  uVar2 = FUN_10056380(0,0);
  if (*(char *)(param_2 + 10) < '\0') {
    FUN_10056c70(param_4,0x69,&local_340,0x40);
    FUN_100073c0(param_1,&local_340,auStack_300);
    uVar4 = (uint)local_340;
    pbVar5 = local_33f;
    while (bVar1 = uVar4 != 0, uVar4 = uVar4 - 1, bVar1) {
      *pbVar5 = ~*pbVar5;
      pbVar5 = pbVar5 + 1;
    }
    if (local_44 != 0) {
      local_44 = 1;
      local_42[0] = 0x78;
    }
    FUN_100568b0(uVar2,0x66,auStack_ee,local_f0);
    FUN_100568b0(uVar2,0x69,local_33f,local_340);
    FUN_100568b0(uVar2,0x6a,local_42,local_44);
    FUN_100568b0(uVar2,0x6e,auStack_2fc,8);
    FUN_10058a70(param_3,uVar2);
    FUN_100563d0(uVar2);
  }
  else {
    uVar3 = FUN_10056380(0,0);
    FUN_10056ae0(uVar3,100,0x10091911);
    FUN_10058a10(param_3,1);
    FUN_10058a70(param_3,uVar3);
    FUN_100563d0(uVar3);
    FUN_100563d0(uVar2);
  }
  return;
}

