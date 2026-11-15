
uint FUN_10079b20(int *param_1,uint param_2,uint param_3,undefined4 param_4,uint param_5)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  
  if (((((param_3 != 0) && (0x17 < param_2)) && (*param_1 == 0x49564131)) &&
      ((uVar1 = param_1[3], uVar1 != 0 && ((uVar1 & 0xff000000) == 0)))) &&
     (uVar4 = (uVar1 + 1) * 8 + 0x10, uVar4 <= param_2)) {
    if (param_3 == param_1[4]) {
      uVar5 = 0;
LAB_10079bec:
      uVar3 = param_1[uVar5 * 2 + 5];
      uVar1 = param_1[uVar5 * 2 + 7];
      if ((uVar3 < uVar1) && (uVar1 <= param_2 - uVar4)) {
        if (uVar1 - uVar3 < param_5) {
          param_5 = uVar1 - uVar3;
        }
        FUN_100539c0(param_4,(int)param_1 + uVar3 + uVar4,param_5);
        return param_5;
      }
    }
    else if ((uint)param_1[4] <= param_3) {
      uVar3 = 1;
      uVar1 = uVar1 - 1;
      while (uVar3 <= uVar1) {
        uVar5 = uVar3 + uVar1 >> 1;
        uVar2 = *(uint *)((int)param_1 + ((uVar3 + uVar1) * 4 & 0xfffffff8) + 0x10);
        if (param_3 == uVar2) goto LAB_10079bec;
        if (param_3 < uVar2) {
          uVar1 = uVar5 - 1;
        }
        else {
          uVar3 = uVar5 + 1;
        }
      }
    }
  }
  return 0;
}

