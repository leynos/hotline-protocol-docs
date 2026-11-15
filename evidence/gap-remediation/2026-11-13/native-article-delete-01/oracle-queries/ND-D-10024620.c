
void FUN_10024620(undefined4 param_1,uint param_2,int *param_3,uint param_4,undefined4 param_5)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  int iVar9;
  
  uVar3 = param_3[1];
  iVar9 = *param_3;
  if ((uVar3 != 0) && (iVar9 != 0)) {
    iVar1 = uVar3 * 8;
    iVar4 = FUN_10052a10(iVar1);
    iVar8 = (iVar9 + -1) * param_2 + 0x200;
    iVar5 = FUN_1002c3b0(param_1,iVar8,iVar4,iVar1,0);
    if (iVar1 != iVar5) {
      FUN_10027c30(1,0xb);
    }
    uVar7 = 0;
    uVar6 = uVar3 - 1;
    while (uVar7 != uVar6) {
      uVar2 = uVar7 + uVar6 >> 1;
      if (*(uint *)(iVar4 + ((uVar7 + uVar6) * 4 & 0xfffffff8)) < param_4) {
        uVar7 = uVar2 + 1;
      }
      else {
        uVar6 = uVar2;
      }
    }
    if (param_4 == *(uint *)(iVar4 + uVar7 * 8)) {
      while (uVar6 = uVar6 + 1, uVar6 != uVar3) {
        *(undefined4 *)(iVar4 + uVar6 * 8 + -8) = *(undefined4 *)(iVar4 + uVar6 * 8);
        *(undefined4 *)(iVar4 + uVar6 * 8 + -4) = *(undefined4 *)(iVar4 + uVar6 * 8 + 4);
      }
      uVar6 = (iVar1 + (param_2 - 1)) / param_2;
      uVar3 = uVar3 - 1;
      param_3[1] = uVar3;
      if ((uVar6 != (param_2 + uVar3 * 8 + -1) / param_2) &&
         (FUN_10024150(param_1,param_2,param_5,iVar9 + (uVar6 - 1),1), uVar3 == 0)) {
        *param_3 = 0;
      }
    }
    FUN_1002c440(param_1,iVar8 + uVar7 * 8,iVar4 + uVar7 * 8,(uVar3 - uVar7) * 8,0);
    FUN_10052c10(iVar4);
  }
  return;
}

