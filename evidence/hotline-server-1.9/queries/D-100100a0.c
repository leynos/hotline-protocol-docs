
void FUN_100100a0(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  undefined4 uVar5;
  char cVar6;
  undefined1 local_820;
  undefined1 auStack_81f [2055];
  
  uVar1 = FUN_10056380(0,0);
  iVar2 = FUN_10007ee0(param_1,param_2);
  uVar3 = FUN_10056b60(param_4,0xca,&local_820,0x800);
  if (uVar3 < 6) {
    FUN_100055a0(param_1,iVar2,0,uVar1);
  }
  else {
    iVar4 = FUN_1002b0e0(iVar2,&local_820,uVar3,0,0x212,0);
    if (iVar4 == 0) {
      uVar5 = FUN_10056380(0,0);
      FUN_10056ae0(uVar5,100,s_ECannot_get_file_list_because_th_1009075c);
      FUN_10058a10(param_3,1);
      FUN_10058a70(param_3,uVar5);
      FUN_100563d0(uVar5);
      FUN_1002b2f0(0);
      if (iVar2 != 0) {
        FUN_1002b2f0(iVar2);
      }
      FUN_100563d0(uVar1);
      return;
    }
    cVar6 = FUN_10008a90(param_1,param_2,0x1e);
    if (cVar6 == '\0') {
      FUN_1002bce0(iVar4,&local_820,0);
      FUN_100541e0(auStack_81f,local_820,0);
      uVar3 = FUN_1006ce10(s_ECannot_get_file_list_because_th_1009075c + 0x46,8,auStack_81f,
                           local_820);
      uVar3 = (-uVar3 | uVar3) >> 0x1f;
    }
    else {
      uVar3 = 0;
    }
    FUN_100055a0(param_1,iVar4,uVar3,uVar1);
    FUN_1002b2f0(iVar4);
  }
  FUN_10058a70(param_3,uVar1);
  if (iVar2 != 0) {
    FUN_1002b2f0(iVar2);
  }
  FUN_100563d0(uVar1);
  return;
}

