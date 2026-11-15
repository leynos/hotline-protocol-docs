
void FUN_1000f260(int param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  short sVar1;
  char cVar8;
  undefined4 uVar2;
  uint uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  int iVar7;
  undefined4 *puVar9;
  
  cVar8 = FUN_10008a90(param_1,param_2,0x15);
  if (cVar8 == '\0') {
    uVar2 = FUN_10056380(0,0);
    FUN_10056ae0(uVar2,100,s_8You_are_not_allowed_to_read_new_10090520 + 0x39);
    FUN_10058a10(param_3,1);
    FUN_10058a70(param_3,uVar2);
    FUN_100563d0(uVar2);
  }
  else {
    uVar3 = FUN_100567c0(param_4,0x65);
    if (uVar3 < 0x2001) {
      uVar2 = FUN_10004110(param_1,param_4,param_2 + 0x38);
      uVar4 = FUN_10056380(0,0);
      FUN_10058a70(param_3,uVar4);
      uVar5 = *(undefined4 *)(param_1 + 4);
      uVar6 = FUN_10053290();
      iVar7 = FUN_1006d220(uVar6,uVar2,0xffffffff);
      if (iVar7 == *(int *)(param_2 + 0x13c)) {
        sVar1 = *(short *)(param_2 + 0x140);
        *(short *)(param_2 + 0x140) = sVar1 + 1;
        if (sVar1 == 4) {
          FUN_100583b0(*(undefined4 *)(param_2 + 4));
          FUN_100063c0(param_1,*(undefined4 *)(param_2 + 0x10));
          FUN_100068e0(param_1,param_2,s_8You_are_not_allowed_to_read_new_10090520 + 0xa8);
          FUN_10053310(uVar5);
          FUN_100563d0(uVar4);
          return;
        }
      }
      else {
        *(int *)(param_2 + 0x13c) = iVar7;
        *(undefined2 *)(param_2 + 0x140) = 0;
      }
      FUN_100568b0(uVar4,0x65,uVar6,uVar2);
      for (puVar9 = *(undefined4 **)(param_1 + 0x34); puVar9 != (undefined4 *)0x0;
          puVar9 = (undefined4 *)*puVar9) {
        cVar8 = FUN_10058600(puVar9[1]);
        if ((cVar8 != '\0') && (cVar8 = FUN_10008a90(param_1,puVar9,0x14), cVar8 != '\0')) {
          FUN_10058ca0(puVar9[1],0x66,uVar4);
        }
      }
      FUN_10053310(uVar5);
      FUN_100563d0(uVar4);
    }
    else {
      uVar2 = FUN_10056380(0,0);
      FUN_10056ae0(uVar2,100,s_8You_are_not_allowed_to_read_new_10090520 + 0x70);
      FUN_10058a10(param_3,1);
      FUN_10058a70(param_3,uVar2);
      FUN_100563d0(uVar2);
    }
  }
  return;
}

