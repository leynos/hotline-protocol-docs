
undefined4 FUN_1002ddf0(int param_1,int param_2,uint param_3)

{
  short sVar1;
  int iVar2;
  undefined **ppuVar3;
  int *piVar4;
  uint uVar5;
  uint uVar6;
  int *piVar7;
  undefined **local_4c;
  
  ppuVar3 = &_toc;
  if (param_1 == 0) {
    FUN_10027c30(1,2);
  }
  if (*(int *)(param_1 + 0x4c) == 0) {
    FUN_10027c30(1,3);
  }
  piVar7 = *(int **)(param_1 + 0x4c);
  if (param_3 == 0) {
    if (*(char *)(piVar7 + 0xa4) != '\0') {
      FUN_1002e120(param_1);
      FUN_1002d2c0(param_1,piVar7 + 0x10,piVar7[5]);
    }
  }
  else {
LAB_1002de74:
    while( true ) {
      iVar2 = *piVar7;
      if (iVar2 != 3) break;
      if (piVar7[0xd] != 0) {
        FUN_10001bd0((int)ppuVar3 + 0x354f);
        FUN_10027c30(1,8);
      }
LAB_1002e0d8:
      uVar6 = 0;
      *piVar7 = *piVar7 + 1;
      piVar7[1] = 0;
LAB_1002e0f0:
      if (param_3 <= uVar6) {
        return 1;
      }
      param_2 = param_2 + uVar6;
      param_3 = param_3 - uVar6;
    }
    if (iVar2 < 3) {
      if (iVar2 == 1) {
        if (piVar7[6] != 0x46494c50) {
          FUN_10027c30(1,8);
        }
        if (*(short *)(piVar7 + 7) != 1) {
          FUN_10027c30(1,7);
        }
        goto LAB_1002e0d8;
      }
      if (iVar2 < 1) {
        if (iVar2 < 0) goto LAB_1002dfc0;
        piVar4 = piVar7 + 6;
        uVar5 = 0x18;
      }
      else {
        piVar4 = piVar7 + 0xc;
        uVar5 = 0x10;
      }
LAB_1002dfec:
      uVar6 = uVar5 - piVar7[1];
      if (param_3 < uVar5 - piVar7[1]) {
        uVar6 = param_3;
      }
      .glue::BlockMoveData(param_2,(int)piVar4 + piVar7[1],uVar6);
      iVar2 = piVar7[1];
      piVar7[1] = iVar2 + uVar6;
      ppuVar3 = local_4c;
      if (uVar5 <= iVar2 + uVar6) {
        *piVar7 = *piVar7 + 1;
        piVar7[1] = 0;
      }
      goto LAB_1002e0f0;
    }
    if (iVar2 == 5) {
      if (param_3 == 0) goto LAB_1002dfc0;
      *piVar7 = 2;
      goto LAB_1002de74;
    }
    if (iVar2 < 5) {
      uVar5 = piVar7[0xf];
      iVar2 = piVar7[0xc];
      if (iVar2 == 0x494e464f) {
        if (0x250 < uVar5) {
          uVar5 = 0x250;
        }
        *(undefined1 *)(piVar7 + 0xa4) = 1;
        piVar7[5] = uVar5;
        piVar4 = piVar7 + 0x10;
        goto LAB_1002dfec;
      }
      if (iVar2 < 0x494e464f) {
        if (iVar2 == 0x44415441) {
          sVar1 = *(short *)(param_1 + 0x50);
          iVar2 = piVar7[2];
LAB_1002e044:
          uVar6 = uVar5 - piVar7[1];
          if (param_3 < uVar5 - piVar7[1]) {
            uVar6 = param_3;
          }
          FUN_1002e370((int)sVar1,iVar2 + piVar7[1],param_2,uVar6);
          iVar2 = piVar7[1];
          piVar7[1] = iVar2 + uVar6;
          if (uVar5 <= iVar2 + uVar6) {
            *piVar7 = *piVar7 + 1;
            piVar7[1] = 0;
          }
          goto LAB_1002e0f0;
        }
      }
      else if (iVar2 == 0x4d414352) {
        sVar1 = *(short *)(param_1 + 0x52);
        iVar2 = piVar7[3];
        goto LAB_1002e044;
      }
      uVar6 = uVar5 - piVar7[1];
      if (param_3 < uVar5 - piVar7[1]) {
        uVar6 = param_3;
      }
      iVar2 = piVar7[1];
      piVar7[1] = iVar2 + uVar6;
      if (uVar5 <= iVar2 + uVar6) {
        *piVar7 = *piVar7 + 1;
        piVar7[1] = 0;
      }
      goto LAB_1002e0f0;
    }
LAB_1002dfc0:
    if (*(char *)(piVar7 + 0xa4) != '\0') {
      FUN_1002e120(param_1);
      FUN_1002d2c0(param_1,piVar7 + 0x10,piVar7[5]);
    }
  }
  return 0;
}

