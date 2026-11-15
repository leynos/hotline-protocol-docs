
void FUN_100568b0(int *param_1,short param_2,int param_3,uint param_4)

{
  int iVar1;
  undefined2 *puVar2;
  int iVar3;
  short *psVar4;
  int iVar5;
  
  if ((param_1 == (int *)0x0) || (param_2 == 0)) {
    FUN_10027c30(1,2);
  }
  if (param_4 != 0) {
    if (0xffff < param_4) {
      FUN_10001bd0(s_UFieldData__AddField_____maximum_10094a08);
      FUN_10027c30(1,10);
    }
    iVar5 = *param_1;
    if (iVar5 == 0) {
      iVar5 = FUN_10052c50(param_1[1] + param_4 + 6,0);
      iVar1 = FUN_10053290();
      puVar2 = (undefined2 *)(iVar1 + param_1[1]);
      *puVar2 = 1;
      puVar2[1] = param_2;
      puVar2[2] = (short)param_4;
      if (param_3 != 0) {
        FUN_100539c0(puVar2 + 3,param_3,param_4);
      }
      *param_1 = iVar5;
      FUN_10053310(iVar5);
    }
    else {
      iVar1 = FUN_10052f80(iVar5);
      FUN_10052ee0(iVar5,iVar1 + param_4 + 4);
      iVar3 = FUN_10053290(iVar5);
      *(short *)(iVar3 + param_1[1]) = *(short *)(iVar3 + param_1[1]) + 1;
      psVar4 = (short *)(iVar3 + iVar1);
      *psVar4 = param_2;
      psVar4[1] = (short)param_4;
      if (param_3 != 0) {
        FUN_100539c0(psVar4 + 2,param_3,param_4);
      }
      FUN_10053310(iVar5);
    }
    if (param_1[2] != 0) {
      FUN_10052c10(param_1[2]);
      FUN_10052c10(param_1[3]);
      param_1[3] = 0;
      param_1[2] = 0;
      param_1[4] = 0;
      *(undefined2 *)(param_1 + 6) = 0;
    }
  }
  return;
}

