
int FUN_1006cf70(undefined4 param_1,uint param_2,char *param_3,int param_4,char *param_5,int param_6
                )

{
  bool bVar1;
  char cVar2;
  char cVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  char *pcVar7;
  int iVar8;
  int iVar9;
  
  uVar4 = FUN_10052f80();
  iVar9 = 0;
  if (param_2 < uVar4) {
    iVar8 = uVar4 - param_2;
    if (param_4 == param_6) {
      if ((param_4 == 1) && (param_6 == 1)) {
        cVar2 = *param_3;
        cVar3 = *param_5;
        iVar5 = FUN_10053290(param_1);
        pcVar7 = (char *)(iVar5 + param_2);
        while (bVar1 = iVar8 != 0, iVar8 = iVar8 + -1, bVar1) {
          if (*pcVar7 == cVar2) {
            *pcVar7 = cVar3;
            iVar9 = iVar9 + 1;
          }
          pcVar7 = pcVar7 + 1;
        }
        FUN_10053310(param_1);
      }
      else {
        iVar5 = FUN_10053290(param_1);
        iVar5 = iVar5 + param_2;
        iVar8 = iVar5 + iVar8;
        while (iVar5 = FUN_1006ce10(param_3,param_4,iVar5,iVar8 - iVar5), iVar5 != 0) {
          FUN_100539c0(iVar5,param_5,param_6);
          iVar5 = iVar5 + param_6;
          iVar9 = iVar9 + 1;
        }
        FUN_10053310(param_1);
      }
    }
    else {
      while( true ) {
        iVar5 = FUN_10053290(param_1);
        iVar6 = FUN_1006ce10(param_3,param_4,iVar5 + param_2,iVar8);
        if (iVar6 == 0) break;
        iVar6 = iVar6 - iVar5;
        FUN_10053310(param_1);
        FUN_10053670(param_1,iVar6,param_4,param_5,param_6);
        iVar8 = iVar8 - ((iVar6 + param_4) - param_2);
        if (iVar8 == 0) goto LAB_1006d114;
        iVar9 = iVar9 + 1;
        param_2 = iVar6 + param_6;
      }
      FUN_10053310(param_1);
    }
  }
  else {
    iVar9 = 0;
  }
LAB_1006d114:
  return iVar9;
}

