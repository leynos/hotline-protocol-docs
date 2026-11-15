
int FUN_1002d830(int param_1,int param_2,uint param_3)

{
  short sVar1;
  undefined **ppuVar2;
  uint *puVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  uint *puVar8;
  undefined **ppuStack_4c;
  
  ppuVar2 = &_toc;
  iVar7 = 0;
  if (param_1 == 0) {
    FUN_10027c30(1,2);
  }
  if (*(int *)(param_1 + 0x48) == 0) {
    FUN_10027c30(1,3);
  }
  puVar8 = *(uint **)(param_1 + 0x48);
  do {
    if (6 < *puVar8) {
      return iVar7;
    }
    switch(ppuVar2[*puVar8 + 0xd33]) {
    case (undefined *)0x1002d8a4:
      puVar3 = puVar8 + 4;
      uVar4 = 0x18;
      break;
    case (undefined *)0x1002d8b0:
      puVar3 = puVar8 + 0x12;
      uVar4 = 0x10;
      break;
    case (undefined *)0x1002d8bc:
      puVar3 = puVar8 + 0x16;
      uVar4 = puVar8[0x15];
      break;
    case (undefined *)0x1002d8c8:
      puVar3 = puVar8 + 10;
      uVar4 = 0x10;
      break;
    case (undefined *)0x1002d8d4:
      uVar5 = puVar8[0xd];
      sVar1 = *(short *)(param_1 + 0x50);
      uVar4 = puVar8[2];
      goto LAB_1002d908;
    case (undefined *)0x1002d8e4:
      puVar3 = puVar8 + 0xe;
      uVar4 = 0x10;
      break;
    case (undefined *)0x1002d8f0:
      uVar5 = puVar8[0x11];
      sVar1 = *(short *)(param_1 + 0x52);
      uVar4 = puVar8[3];
LAB_1002d908:
      uVar6 = uVar5 - puVar8[1];
      if (param_3 < uVar5 - puVar8[1]) {
        uVar6 = param_3;
      }
      FUN_1002e300((int)sVar1,uVar4 + puVar8[1],param_2,uVar6);
      uVar4 = puVar8[1];
      puVar8[1] = uVar4 + uVar6;
      if (uVar5 <= uVar4 + uVar6) {
        *puVar8 = *puVar8 + 1;
        puVar8[1] = 0;
      }
      goto LAB_1002d9b0;
    }
    uVar6 = uVar4 - puVar8[1];
    if (param_3 < uVar4 - puVar8[1]) {
      uVar6 = param_3;
    }
    .glue::BlockMoveData((int)puVar3 + puVar8[1],param_2,uVar6);
    uVar5 = puVar8[1];
    puVar8[1] = uVar5 + uVar6;
    ppuVar2 = ppuStack_4c;
    if (uVar4 <= uVar5 + uVar6) {
      *puVar8 = *puVar8 + 1;
      puVar8[1] = 0;
    }
LAB_1002d9b0:
    iVar7 = iVar7 + uVar6;
    if (param_3 <= uVar6) {
      return iVar7;
    }
    param_2 = param_2 + uVar6;
    param_3 = param_3 - uVar6;
  } while( true );
}

