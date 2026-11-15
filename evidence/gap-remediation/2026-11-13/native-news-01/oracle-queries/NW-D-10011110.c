
void FUN_10011110(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  char cVar2;
  undefined1 auStack_a10 [128];
  short local_950 [2];
  int local_94c;
  int local_948;
  undefined4 local_944;
  undefined4 local_940;
  undefined1 *local_924;
  undefined1 auStack_920 [256];
  undefined1 auStack_820 [2056];
  
  FUN_10056c70(param_4,0x142,auStack_920,0x100);
  uVar1 = FUN_10056b60(param_4,0x145,auStack_820,0x800);
  cVar2 = FUN_10008ad0(param_1,param_2,0x22);
  if (cVar2 == '\0') {
    local_944 = FUN_10056380(0,0);
    FUN_10056ae0(local_944,100,0x10090b4f);
    FUN_10058a10(param_3,1);
    FUN_10058a70(param_3,local_944);
    FUN_100563d0(local_944);
  }
  else {
    local_94c = FUN_10007f40(param_1,param_2);
    local_948 = FUN_1002b0e0(local_94c,auStack_820,uVar1,auStack_920,5,local_950);
    if (local_948 == 0) {
      if (local_950[0] == 0) {
        FUN_1000ef30(param_3,0x10090b7e,auStack_920);
      }
      else {
        FUN_1000ef30(param_3,0x10090bd1,auStack_920);
      }
      FUN_1002b2f0(local_948);
      if (local_94c != 0) {
        FUN_1002b2f0(local_94c);
      }
    }
    else {
      local_924 = auStack_a10 + 0x80;
      FUN_10022670(local_948,0x33313133,auStack_920,0x10090c2e);
      local_940 = FUN_10056380(0,0);
      FUN_10058a70(param_3,local_940);
      FUN_100563d0(local_940);
      FUN_100068e0(param_1,param_2,0x10090c52,auStack_920);
      FUN_1002b2f0(local_948);
      if (local_94c != 0) {
        FUN_1002b2f0(local_94c);
      }
    }
  }
  return;
}

