
void FUN_10010b70(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  int iVar1;
  int iVar2;
  char cVar3;
  undefined1 auStack_920 [128];
  short local_860 [2];
  int local_85c;
  int local_858;
  undefined4 local_854;
  undefined4 local_850;
  undefined4 local_84c;
  undefined4 local_844;
  undefined1 *local_82c;
  undefined1 auStack_828 [2060];
  
  iVar1 = FUN_10007f40();
  local_85c = iVar1;
  iVar2 = FUN_10056b60(param_4,0x145,auStack_828,0x800);
  local_858 = FUN_1002b0e0(iVar1,auStack_828,iVar2,0,2,local_860);
  if ((local_858 == 0) || (cVar3 = FUN_1002cac0(local_858,iVar1), cVar3 != '\0')) {
    local_854 = FUN_10056380(0,0);
    FUN_10056ae0(local_854,100,0x10090990);
    FUN_10058a10(param_3,1);
    FUN_10058a70(param_3,local_854);
    FUN_100563d0(local_854);
    FUN_1002b2f0(local_858);
    if (local_85c != 0) {
      FUN_1002b2f0(local_85c);
    }
  }
  else if ((local_860[0] == 3) && (cVar3 = FUN_10008ad0(param_1,param_2,0x25), cVar3 == '\0')) {
    local_850 = FUN_10056380(0,0);
    FUN_10056ae0(local_850,100,0x100909c7);
    FUN_10058a10(param_3,1);
    FUN_10058a70(param_3,local_850);
    FUN_100563d0(local_850);
    FUN_1002b2f0(local_858);
    if (local_85c != 0) {
      FUN_1002b2f0(local_85c);
    }
  }
  else if ((local_860[0] == 2) &&
          ((iVar2 == 0 || (cVar3 = FUN_10008ad0(param_1,param_2,0x23), cVar3 == '\0')))) {
    local_84c = FUN_10056380(0,0);
    FUN_10056ae0(local_84c,100,0x100909f3);
    FUN_10058a10(param_3,1);
    FUN_10058a70(param_3,local_84c);
    FUN_100563d0(local_84c);
    FUN_1002b2f0(local_858);
    if (local_85c != 0) {
      FUN_1002b2f0(local_85c);
    }
  }
  else {
    local_82c = auStack_920 + 0x80;
    FUN_1002ba20(local_858);
    local_844 = FUN_10056380(0,0);
    FUN_10058a70(param_3,local_844);
    FUN_100563d0(local_844);
    FUN_1002b2f0(local_858);
    if (local_85c != 0) {
      FUN_1002b2f0(local_85c);
    }
  }
  return;
}

