
void FUN_10015e70(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  char cVar7;
  undefined4 uVar1;
  undefined2 uVar6;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  undefined1 *puVar8;
  undefined1 local_160;
  undefined1 auStack_15f [63];
  undefined1 local_120;
  undefined1 auStack_11f [259];
  
  cVar7 = FUN_10008a90(param_1,param_2,0x16);
  if (cVar7 == '\0') {
    uVar1 = FUN_10056380(0,0);
    FUN_10056ae0(uVar1,100,0x10091a53);
    FUN_10058a10(param_3,1);
    FUN_10058a70(param_3,uVar1);
    FUN_100563d0(uVar1);
  }
  else {
    uVar6 = FUN_10056b90(param_4,0x67);
    iVar2 = FUN_10004730(param_1,uVar6);
    if (iVar2 != 0) {
      cVar7 = FUN_10008a90(param_1,iVar2,0x17);
      if (cVar7 != '\0') {
        FUN_1000ef30(param_3,0x10091a7c,iVar2 + 0x38);
        return;
      }
      uVar1 = FUN_10056380(0,0);
      iVar3 = FUN_10056b90(param_4,0x71);
      if (iVar3 == 1) {
        FUN_10056ae0(uVar1,0x65,0x10090e0b);
        FUN_10058ca0(*(undefined4 *)(iVar2 + 4),0x68,uVar1);
        FUN_100063c0(param_1,*(undefined4 *)(iVar2 + 0x10));
      }
      else if (iVar3 == 2) {
        FUN_10056ae0(uVar1,0x65,0x10090de0);
        FUN_10058ca0(*(undefined4 *)(iVar2 + 4),0x68,uVar1);
        iVar4 = FUN_100567c0(param_4,0x65);
        if (iVar4 == 0) {
          local_160 = 0;
        }
        else {
          local_160 = FUN_10056b60(param_4,0x65,auStack_15f,0x3f);
        }
        FUN_10006230(param_1,*(undefined4 *)(iVar2 + 0x10),*(undefined4 *)(iVar2 + 0x10),&local_160)
        ;
      }
      FUN_100583b0(*(undefined4 *)(iVar2 + 4));
      FUN_10028dc0(100,0,0,0,0,0,0);
      puVar8 = (undefined1 *)(iVar2 + 0x38);
      if (*(char *)(iVar2 + 0x38) == '\0') {
        uVar5 = FUN_10058270(*(undefined4 *)(iVar2 + 4));
        local_120 = FUN_1006d550(uVar5,auStack_11f,0xff);
        puVar8 = &local_120;
      }
      if (iVar3 == 2) {
        FUN_100068e0(param_1,param_2,0x10091abe,puVar8);
      }
      else if (iVar3 == 1) {
        FUN_100068e0(param_1,param_2,0x10091adf,puVar8);
      }
      else {
        FUN_100068e0(param_1,param_2,0x10091b00,puVar8);
      }
      FUN_100563d0(uVar1);
    }
    uVar1 = FUN_10056380(0,0);
    FUN_10058a70(param_3,uVar1);
    FUN_100563d0(uVar1);
  }
  return;
}

