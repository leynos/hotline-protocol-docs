
void FUN_10014df0(undefined4 param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  bool bVar1;
  undefined4 uVar2;
  uint uVar3;
  byte *pbVar4;
  undefined1 local_628;
  undefined1 auStack_627 [63];
  undefined2 local_5e8 [2];
  undefined1 auStack_5e4 [524];
  undefined2 local_3d8;
  undefined1 auStack_3d6 [66];
  undefined2 local_394;
  undefined1 auStack_392 [66];
  ushort local_350;
  byte local_34e [34];
  ushort local_32c;
  char local_32a [34];
  undefined1 auStack_308 [700];
  ushort local_4c;
  undefined1 auStack_4a [50];
  
  if ((*(byte *)(param_2 + 10) >> 6 & 1) == 0) {
    uVar2 = FUN_10056380(0,0);
    FUN_10056ae0(uVar2,100,0x1009195c);
    FUN_10058a10(param_3,1);
    FUN_10058a70(param_3,uVar2);
    FUN_100563d0(uVar2);
  }
  else {
    FUN_1006cd50(local_5e8,0x2de);
    local_5e8[0] = 1;
    local_3d8 = FUN_10056b60(param_4,0x66,auStack_3d6,0x40);
    local_394 = FUN_10056b60(param_4,0x6f,auStack_392,0x40);
    local_350 = FUN_10056b60(param_4,0x69,local_34e,0x20);
    local_32c = FUN_10056b60(param_4,0x6a,local_32a,0x20);
    FUN_10056b60(param_4,0x6e,auStack_5e4,8);
    uVar3 = (uint)local_350;
    pbVar4 = local_34e;
    while (bVar1 = uVar3 != 0, uVar3 = uVar3 - 1, bVar1) {
      *pbVar4 = ~*pbVar4;
      pbVar4 = pbVar4 + 1;
    }
    local_628 = (undefined1)local_350;
    FUN_100539c0(auStack_627,local_34e,local_350 & 0xff);
    FUN_100541e0(auStack_627,local_628,0);
    if ((local_32c == 1) && (local_32a[0] == '\0')) {
      FUN_100073c0(param_1,&local_628,auStack_308);
      if (local_4c < 0x20) {
        local_32c = local_4c;
      }
      else {
        local_32c = 0x1f;
      }
      FUN_100539c0(local_32a,auStack_4a,local_32c);
    }
    FUN_100075e0(param_1,local_5e8);
    uVar2 = FUN_10056380(0,0);
    FUN_10058a70(param_3,uVar2);
    FUN_100563d0(uVar2);
    FUN_10005d30(param_1,&local_628,local_5e8);
    FUN_10006fe0(param_1,param_2,0x100919ac,&local_628);
    FUN_100068e0(param_1,param_2,0x100919b3,&local_628);
  }
  return;
}

