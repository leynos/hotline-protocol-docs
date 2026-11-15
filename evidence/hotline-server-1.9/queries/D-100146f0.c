
void FUN_100146f0(undefined4 param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  bool bVar1;
  undefined4 uVar2;
  uint uVar3;
  byte *pbVar4;
  uint local_370;
  undefined1 local_348;
  undefined1 auStack_347 [63];
  undefined2 local_308 [2];
  uint local_304;
  uint local_300;
  undefined2 local_f8;
  undefined1 auStack_f6 [66];
  undefined2 local_b4;
  undefined1 auStack_b2 [66];
  ushort local_70;
  byte local_6e [34];
  undefined2 local_4c;
  undefined1 auStack_4a [50];
  
  if ((*(byte *)(param_2 + 9) >> 1 & 1) == 0) {
    uVar2 = FUN_10056380(0,0);
    FUN_10056ae0(uVar2,100,0x100917a7);
    FUN_10058a10(param_3,1);
    FUN_10058a70(param_3,uVar2);
    FUN_100563d0(uVar2);
  }
  else {
    FUN_1006cd50(local_308,0x2de);
    local_308[0] = 1;
    local_f8 = FUN_10056b60(param_4,0x66,auStack_f6,0x40);
    local_b4 = FUN_10056b60(param_4,0x6f,auStack_b2,0x40);
    local_70 = FUN_10056b60(param_4,0x69,local_6e,0x20);
    local_4c = FUN_10056b60(param_4,0x6a,auStack_4a,0x20);
    FUN_10056b60(param_4,0x6e,&local_304,8);
    local_370 = local_304 & 0xffffffef;
    if (((local_370 & ~*(uint *)(param_2 + 8)) == 0) &&
       ((local_300 & ~*(uint *)(param_2 + 0xc)) == 0)) {
      uVar3 = (uint)local_70;
      pbVar4 = local_6e;
      while (bVar1 = uVar3 != 0, uVar3 = uVar3 - 1, bVar1) {
        *pbVar4 = ~*pbVar4;
        pbVar4 = pbVar4 + 1;
      }
      local_348 = (undefined1)local_70;
      FUN_100539c0(auStack_347,local_6e,local_70 & 0xff);
      FUN_100071a0(param_1,local_308);
      uVar2 = FUN_10056380(0,0);
      FUN_10058a70(param_3,uVar2);
      FUN_100563d0(uVar2);
      FUN_10006fe0(param_1,param_2,0x10091877,&local_348);
      FUN_100068e0(param_1,param_2,0x1009187e,&local_348);
    }
    else {
      uVar2 = FUN_10056380(0,0);
      FUN_10056ae0(uVar2,100,0x100917d3);
      FUN_10058a10(param_3,1);
      FUN_10058a70(param_3,uVar2);
      FUN_100563d0(uVar2);
    }
  }
  return;
}

