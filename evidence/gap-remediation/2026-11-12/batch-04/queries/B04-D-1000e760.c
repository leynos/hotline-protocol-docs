
undefined4 FUN_1000e760(int param_1,int param_2,int param_3)

{
  bool bVar1;
  int iVar2;
  char cVar4;
  undefined4 uVar3;
  undefined4 *puVar5;
  undefined4 *puVar6;
  char *pcVar7;
  
  iVar2 = *(int *)(param_1 + 0x54);
  if (iVar2 == 0) {
LAB_1000ea04:
    iVar2 = *(int *)(param_1 + 0x3c);
    if (iVar2 == 0) {
LAB_1000eafc:
      iVar2 = *(int *)(param_1 + 0x48);
      if (iVar2 == 0) {
LAB_1000ec1c:
        uVar3 = 0;
      }
      else {
        puVar5 = *(undefined4 **)(param_1 + 0x44);
        do {
          bVar1 = iVar2 == 0;
          iVar2 = iVar2 + -1;
          if (bVar1) goto LAB_1000ec1c;
          puVar6 = (undefined4 *)*puVar5;
          puVar5 = puVar5 + 1;
        } while (puVar6[3] != param_3);
        if (puVar6[0xb] == param_2) {
          FUN_10055630(param_1 + 0x44,puVar6);
          FUN_100069b0(param_1,*puVar6,s_Download_connection_closed_1009043b);
          FUN_1006d3e0(*puVar6);
          if (puVar6[1] != 0) {
            FUN_10026670(puVar6[1],1);
          }
          if (puVar6[2] != 0) {
            FUN_1002b2f0(puVar6[2]);
          }
          FUN_1006d290(puVar6);
          if (*(uint *)(param_1 + 0x42c) < *(uint *)(param_1 + 0x428)) {
            *(undefined4 *)(param_1 + 0x42c) = *(undefined4 *)(param_1 + 0x428);
          }
          if (*(int *)(param_1 + 0x8c) != 0) {
            FUN_10021940(*(undefined4 *)(param_1 + 0x8c),*(undefined4 *)(param_1 + 0x428),
                         *(int *)(param_1 + 0x3c) + *(int *)(param_1 + 0x48),
                         *(int *)(param_1 + 0x6c) + *(int *)(param_1 + 0x78),
                         *(undefined4 *)(param_1 + 0x54),*(undefined4 *)(param_1 + 0x42c),
                         *(undefined4 *)(param_1 + 0x430),*(undefined4 *)(param_1 + 0x434));
          }
          uVar3 = 1;
        }
        else {
          uVar3 = 0;
        }
      }
    }
    else {
      puVar5 = *(undefined4 **)(param_1 + 0x38);
      do {
        bVar1 = iVar2 == 0;
        iVar2 = iVar2 + -1;
        if (bVar1) goto LAB_1000eafc;
        puVar6 = (undefined4 *)*puVar5;
        puVar5 = puVar5 + 1;
      } while (puVar6[2] != param_3);
      if (puVar6[9] == param_2) {
        FUN_10055630(param_1 + 0x38,puVar6);
        FUN_100069b0(param_1,*puVar6,s_Download_connection_closed_1009043b);
        FUN_1006d3e0(*puVar6);
        FUN_1002b2f0(puVar6[1]);
        FUN_1006d290(puVar6);
        if (*(uint *)(param_1 + 0x42c) < *(uint *)(param_1 + 0x428)) {
          *(undefined4 *)(param_1 + 0x42c) = *(undefined4 *)(param_1 + 0x428);
        }
        if (*(int *)(param_1 + 0x8c) != 0) {
          FUN_10021940(*(undefined4 *)(param_1 + 0x8c),*(undefined4 *)(param_1 + 0x428),
                       *(int *)(param_1 + 0x3c) + *(int *)(param_1 + 0x48),
                       *(int *)(param_1 + 0x6c) + *(int *)(param_1 + 0x78),
                       *(undefined4 *)(param_1 + 0x54),*(undefined4 *)(param_1 + 0x42c),
                       *(undefined4 *)(param_1 + 0x430),*(undefined4 *)(param_1 + 0x434));
        }
        uVar3 = 1;
      }
      else {
        uVar3 = 0;
      }
    }
  }
  else {
    puVar5 = *(undefined4 **)(param_1 + 0x50);
    do {
      bVar1 = iVar2 == 0;
      iVar2 = iVar2 + -1;
      if (bVar1) goto LAB_1000ea04;
      pcVar7 = (char *)*puVar5;
      puVar5 = puVar5 + 1;
    } while (((*pcVar7 == '\0') || (*(int *)(*(int *)(pcVar7 + 8) + 8) != param_3)) &&
            ((*pcVar7 != '\0' || (*(int *)(*(int *)(pcVar7 + 8) + 0xc) != param_3))));
    if (((*pcVar7 == '\0') || (*(int *)(*(int *)(pcVar7 + 8) + 0x24) == param_2)) &&
       ((*pcVar7 != '\0' || (*(int *)(*(int *)(pcVar7 + 8) + 0x2c) == param_2)))) {
      iVar2 = 0;
      if (pcVar7 != (char *)0x0) {
        if (*pcVar7 == '\0') {
          iVar2 = **(int **)(pcVar7 + 8);
          if ((iVar2 == 0) &&
             (cVar4 = FUN_10055af0(param_1 + 0x34,*(undefined4 *)(*(int *)(pcVar7 + 8) + 0x2c)),
             cVar4 != '\0')) {
            iVar2 = FUN_10058270(*(undefined4 *)(*(int *)(*(int *)(pcVar7 + 8) + 0x2c) + 4));
          }
        }
        else {
          iVar2 = **(int **)(pcVar7 + 8);
          if ((iVar2 == 0) &&
             (cVar4 = FUN_10055af0(param_1 + 0x34,*(undefined4 *)(*(int *)(pcVar7 + 8) + 0x24)),
             cVar4 != '\0')) {
            iVar2 = FUN_10058270(*(undefined4 *)(*(int *)(*(int *)(pcVar7 + 8) + 0x24) + 4));
          }
        }
      }
      FUN_100069b0(param_1,iVar2,s_Download_connection_closed_1009043b);
      FUN_10055630(param_1 + 0x50,pcVar7);
      if (pcVar7 != (char *)0x0) {
        if (*pcVar7 == '\0') {
          if (**(int **)(pcVar7 + 8) != 0) {
            FUN_1006d3e0(**(undefined4 **)(pcVar7 + 8));
          }
          if (*(int *)(*(int *)(pcVar7 + 8) + 4) != 0) {
            FUN_10026670(*(undefined4 *)(*(int *)(pcVar7 + 8) + 4),1);
          }
          FUN_1006d290(*(undefined4 *)(pcVar7 + 8));
        }
        else {
          if (**(int **)(pcVar7 + 8) != 0) {
            FUN_1006d3e0(**(undefined4 **)(pcVar7 + 8));
          }
          FUN_1002b2f0(*(undefined4 *)(*(int *)(pcVar7 + 8) + 4));
          FUN_1006d290(*(undefined4 *)(pcVar7 + 8));
        }
        FUN_1006d290(pcVar7);
      }
      if (*(uint *)(param_1 + 0x42c) < *(uint *)(param_1 + 0x428)) {
        *(undefined4 *)(param_1 + 0x42c) = *(undefined4 *)(param_1 + 0x428);
      }
      if (*(int *)(param_1 + 0x8c) != 0) {
        FUN_10021940(*(undefined4 *)(param_1 + 0x8c),*(undefined4 *)(param_1 + 0x428),
                     *(int *)(param_1 + 0x3c) + *(int *)(param_1 + 0x48),
                     *(int *)(param_1 + 0x6c) + *(int *)(param_1 + 0x78),
                     *(undefined4 *)(param_1 + 0x54),*(undefined4 *)(param_1 + 0x42c),
                     *(undefined4 *)(param_1 + 0x430),*(undefined4 *)(param_1 + 0x434));
      }
      uVar3 = 1;
    }
    else {
      uVar3 = 0;
    }
  }
  return uVar3;
}

