
undefined4 FUN_10024280(undefined4 param_1,int param_2,uint param_3,int *param_4)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  
  iVar3 = param_4[1];
  iVar8 = *param_4;
  if ((iVar3 == 0) || (iVar8 == 0)) {
    uVar4 = 0;
  }
  else {
    iVar1 = iVar3 << 3;
    iVar5 = FUN_10052a10(iVar1);
    iVar8 = FUN_1002c3b0(param_1,(iVar8 + -1) * param_2 + 0x200,iVar5,iVar1,0);
    if (iVar1 != iVar8) {
      FUN_10027c30(1,0xb);
    }
    uVar7 = 0;
    uVar6 = iVar3 - 1;
    while (uVar7 != uVar6) {
      uVar2 = uVar7 + uVar6 >> 1;
      if (*(uint *)(iVar5 + ((uVar7 + uVar6) * 4 & 0xfffffff8)) < param_3) {
        uVar7 = uVar2 + 1;
      }
      else {
        uVar6 = uVar2;
      }
    }
    if (param_3 == *(uint *)(iVar5 + uVar7 * 8)) {
      uVar4 = *(undefined4 *)(iVar5 + uVar7 * 8 + 4);
      FUN_10052c10(iVar5);
    }
    else {
      FUN_10052c10(iVar5);
      uVar4 = 0;
    }
  }
  return uVar4;
}

