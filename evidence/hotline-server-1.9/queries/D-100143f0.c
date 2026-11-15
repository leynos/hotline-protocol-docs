
void FUN_100143f0(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  char cVar3;
  int iVar2;
  undefined1 auStack_a10 [128];
  short local_950 [2];
  int local_94c;
  int local_948;
  undefined4 local_944;
  undefined4 local_940;
  undefined1 *local_924;
  undefined1 local_920;
  undefined1 auStack_91f [255];
  undefined1 auStack_820 [2052];
  
  FUN_10056c70(param_4,0xc9,&local_920,0x100);
  uVar1 = FUN_10056b60(param_4,0xca,auStack_820,0x800);
  cVar3 = FUN_10008ab0(param_1,param_2,5);
  if (cVar3 == '\0') {
    local_944 = FUN_10056380(0,0);
    FUN_10056ae0(local_944,100,0x10091672);
    FUN_10058a10(param_3,1);
    FUN_10058a70(param_3,local_944);
    FUN_100563d0(local_944);
  }
  else {
    local_924 = auStack_a10 + 0x80;
    iVar2 = FUN_10007ee0(param_1,param_2);
    local_94c = iVar2;
    local_920 = FUN_1002c070(auStack_91f,local_920,0);
    local_948 = FUN_1002b0e0(iVar2,auStack_820,uVar1,&local_920,5,local_950);
    if (local_948 == 0) {
      if (local_950[0] == 0) {
        FUN_1000ef30(param_3,0x10091699,&local_920);
      }
      else {
        FUN_1000ef30(param_3,0x100916e5,&local_920);
      }
      FUN_1002b2f0(local_948);
      if (local_94c != 0) {
        FUN_1002b2f0(local_94c);
      }
    }
    else {
      FUN_1002b670(local_948);
      FUN_1002b2f0(local_948);
      if (local_94c != 0) {
        FUN_1002b2f0(local_94c);
      }
      local_940 = FUN_10056380(0,0);
      FUN_10058a70(param_3,local_940);
      FUN_100563d0(local_940);
      FUN_100068e0(param_1,param_2,0x10091756,&local_920);
    }
  }
  return;
}

