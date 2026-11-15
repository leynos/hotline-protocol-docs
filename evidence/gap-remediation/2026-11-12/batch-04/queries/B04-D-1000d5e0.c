
void FUN_1000d5e0(int param_1)

{
  int *piVar1;
  int iVar2;
  char cVar5;
  undefined4 uVar3;
  undefined4 uVar4;
  uint uVar6;
  uint uVar7;
  int iVar8;
  
  if ((*(int *)(param_1 + 0x60) != 0) && (*(int *)(param_1 + 0xc) != 0)) {
    FUN_10057d00();
    iVar2 = FUN_10052f80(*(undefined4 *)(param_1 + 0xc));
    uVar7 = 0;
    while (uVar6 = uVar7, uVar7 = uVar6 + 1, uVar7 <= *(uint *)(param_1 + 0x60)) {
      piVar1 = *(int **)(*(int *)(param_1 + 0x5c) + uVar7 * 4 + -4);
      iVar8 = *piVar1;
      cVar5 = FUN_10055af0(param_1 + 0x34,piVar1[4]);
      if (cVar5 == '\0') {
LAB_1000d6cc:
        FUN_100069b0(param_1,iVar8,s_Download_connection_closed_1009043b);
        FUN_10055630(param_1 + 0x5c,piVar1);
        FUN_1006d3e0(iVar8);
        FUN_1006d290(piVar1);
        uVar7 = uVar6;
      }
      else if (iVar8 == 0) {
        iVar8 = FUN_10057d00();
        if (500 < (uint)(iVar8 - piVar1[2])) {
          FUN_10055630(param_1 + 0x5c,piVar1);
          FUN_1006d290(piVar1);
          FUN_10006860(param_1,s_Download_banner_aborted__no_resp_10090468);
          uVar7 = uVar6;
        }
      }
      else {
        cVar5 = FUN_1006da10(iVar8);
        if (cVar5 == '\0') goto LAB_1000d6cc;
        if (piVar1[3] == 0) {
          uVar3 = FUN_1006ddb0(iVar2);
          uVar4 = FUN_10053290(*(undefined4 *)(param_1 + 0xc));
          FUN_100539c0(uVar3,uVar4,iVar2);
          FUN_10053310(*(undefined4 *)(param_1 + 0xc));
          FUN_1006de10(iVar8,uVar3);
          piVar1[3] = piVar1[3] + iVar2;
          FUN_1006e0b0(iVar8);
          FUN_100069b0(param_1,iVar8,s_Download_banner_complete_1009048e);
        }
      }
    }
  }
  return;
}

