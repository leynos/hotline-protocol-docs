
void FUN_10018760(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 uVar3;
  byte local_118 [264];
  
  uVar1 = FUN_10056b90(param_4,0x72);
  iVar2 = FUN_10004760(param_1,uVar1);
  if (iVar2 != 0) {
    FUN_10056c70(param_4,0x73,local_118,0x100);
    if (local_118[0] == 0) {
      FUN_10052c10(*(undefined4 *)(iVar2 + 0x14));
      *(undefined4 *)(iVar2 + 0x14) = 0;
    }
    else if (*(int *)(iVar2 + 0x14) == 0) {
      uVar3 = FUN_10052ab0(local_118,local_118[0] + 1);
      *(undefined4 *)(iVar2 + 0x14) = uVar3;
    }
    else {
      if (local_118[0] != **(byte **)(iVar2 + 0x14)) {
        uVar3 = FUN_10052ff0(*(undefined4 *)(iVar2 + 0x14),local_118[0] + 1);
        *(undefined4 *)(iVar2 + 0x14) = uVar3;
      }
      FUN_100539c0(*(undefined4 *)(iVar2 + 0x14),local_118,local_118[0] + 1);
    }
    uVar3 = FUN_10056380(0,0);
    FUN_10056a90(uVar3,0x72,uVar1);
    FUN_10056ae0(uVar3,0x73,local_118);
    FUN_100048b0(param_1,iVar2,0x77,uVar3);
    FUN_100563d0(uVar3);
  }
  return;
}

