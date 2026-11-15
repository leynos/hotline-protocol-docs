
void FUN_1000cfa0(int param_1)

{
  bool bVar1;
  char *pcVar2;
  char cVar5;
  uint uVar3;
  uint uVar4;
  uint uVar6;
  uint uVar7;
  undefined4 uVar8;
  int iVar9;
  uint uVar10;
  uint uVar11;
  int iVar12;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  
  bVar1 = false;
  uVar10 = 0;
  while (uVar11 = uVar10 + 1, uVar11 <= *(uint *)(param_1 + 0x54)) {
    pcVar2 = *(char **)(*(int *)(param_1 + 0x50) + uVar11 * 4 + -4);
    if (*pcVar2 == '\0') {
      iVar9 = **(int **)(pcVar2 + 8);
      iVar12 = *(int *)(*(int *)(pcVar2 + 8) + 0x2c);
    }
    else {
      iVar9 = **(int **)(pcVar2 + 8);
      iVar12 = *(int *)(*(int *)(pcVar2 + 8) + 0x24);
    }
    cVar5 = FUN_10055af0(param_1 + 0x34,iVar12);
    if ((cVar5 == '\0') || ((iVar9 != 0 && (cVar5 = FUN_1006da10(iVar9), cVar5 == '\0')))) {
      iVar9 = 0;
      if (pcVar2 != (char *)0x0) {
        if (*pcVar2 == '\0') {
          iVar9 = **(int **)(pcVar2 + 8);
          if ((iVar9 == 0) &&
             (cVar5 = FUN_10055af0(param_1 + 0x34,*(undefined4 *)(*(int *)(pcVar2 + 8) + 0x2c)),
             cVar5 != '\0')) {
            iVar9 = FUN_10058270(*(undefined4 *)(*(int *)(*(int *)(pcVar2 + 8) + 0x2c) + 4));
          }
        }
        else {
          iVar9 = **(int **)(pcVar2 + 8);
          if ((iVar9 == 0) &&
             (cVar5 = FUN_10055af0(param_1 + 0x34,*(undefined4 *)(*(int *)(pcVar2 + 8) + 0x24)),
             cVar5 != '\0')) {
            iVar9 = FUN_10058270(*(undefined4 *)(*(int *)(*(int *)(pcVar2 + 8) + 0x24) + 4));
          }
        }
      }
      FUN_100069b0(param_1,iVar9,s_Download_connection_closed_1009043b);
      FUN_10055630(param_1 + 0x50,pcVar2);
      if (pcVar2 != (char *)0x0) {
        if (*pcVar2 == '\0') {
          if (**(int **)(pcVar2 + 8) != 0) {
            FUN_1006d3e0(**(undefined4 **)(pcVar2 + 8));
          }
          if (*(int *)(*(int *)(pcVar2 + 8) + 4) != 0) {
            FUN_10026670(*(undefined4 *)(*(int *)(pcVar2 + 8) + 4),1);
          }
          FUN_1006d290(*(undefined4 *)(pcVar2 + 8));
        }
        else {
          if (**(int **)(pcVar2 + 8) != 0) {
            FUN_1006d3e0(**(undefined4 **)(pcVar2 + 8));
          }
          FUN_1002b2f0(*(undefined4 *)(*(int *)(pcVar2 + 8) + 4));
          FUN_1006d290(*(undefined4 *)(pcVar2 + 8));
        }
        FUN_1006d290(pcVar2);
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
    }
    else {
      if (*pcVar2 == '\0') {
        uVar8 = *(undefined4 *)(*(int *)(pcVar2 + 8) + 0xc);
      }
      else {
        uVar8 = *(undefined4 *)(*(int *)(pcVar2 + 8) + 8);
      }
      uVar7 = 0;
      uVar3 = *(int *)(param_1 + 0x3c) + *(int *)(param_1 + 0x48);
      if (*(ushort *)(param_1 + 0xa4) <= uVar3) {
        uVar7 = (uVar3 - *(ushort *)(param_1 + 0xa4)) + 1;
      }
      uVar3 = 0;
      uVar6 = 0;
      uVar4 = 0;
      while (uVar4 = uVar4 + 1, uVar4 <= *(uint *)(param_1 + 0x3c)) {
        if (*(short *)(*(int *)(*(int *)(param_1 + 0x38) + uVar4 * 4 + -4) + 0x28) ==
            *(short *)(iVar12 + 0x14)) {
          uVar6 = uVar6 + 1;
        }
      }
      uVar4 = 0;
      while (uVar4 = uVar4 + 1, uVar4 <= *(uint *)(param_1 + 0x48)) {
        if (*(short *)(*(int *)(*(int *)(param_1 + 0x44) + uVar4 * 4 + -4) + 0x30) ==
            *(short *)(iVar12 + 0x14)) {
          uVar6 = uVar6 + 1;
        }
      }
      if ((uint)*(ushort *)(param_1 + 0xa6) <= (uVar6 & 0xffff)) {
        uVar3 = ((uVar6 & 0xffff) - (uint)*(ushort *)(param_1 + 0xa6)) + 1;
      }
      if (uVar3 < uVar7) {
        uVar3 = uVar7;
      }
      if (uVar3 == 0) {
        local_2c = uVar8;
        if (iVar12 != 0) {
          local_28 = FUN_10056380(0,0);
          FUN_100568b0(local_28,0x6b,&local_2c,4);
          FUN_10056a90(local_28,0x74,0);
          FUN_10058ca0(*(undefined4 *)(iVar12 + 4),0xd3,local_28);
          FUN_100563d0(local_28);
        }
        FUN_10055630(param_1 + 0x50,pcVar2);
        if (*pcVar2 == '\0') {
          uVar8 = FUN_10057d00();
          *(undefined4 *)(*(int *)(pcVar2 + 8) + 0x10) = uVar8;
          FUN_100554e0(param_1 + 0x44,*(undefined4 *)(pcVar2 + 8));
        }
        else {
          uVar8 = FUN_10057d00();
          *(undefined4 *)(*(int *)(pcVar2 + 8) + 0xc) = uVar8;
          FUN_100554e0(param_1 + 0x38,*(undefined4 *)(pcVar2 + 8));
        }
        FUN_1006d290(pcVar2);
        bVar1 = true;
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
      }
      else {
        iVar9 = uVar11 + uVar3 + -1;
        uVar10 = uVar11;
        if ((*(int *)(pcVar2 + 4) != iVar9) &&
           (*(int *)(pcVar2 + 4) = iVar9, local_34 = uVar8, iVar12 != 0)) {
          local_30 = FUN_10056380(0,0);
          FUN_100568b0(local_30,0x6b,&local_34,4);
          FUN_10056a90(local_30,0x74,iVar9);
          FUN_10058ca0(*(undefined4 *)(iVar12 + 4),0xd3,local_30);
          FUN_100563d0(local_30);
        }
      }
    }
  }
  if (bVar1) {
    FUN_10028dc0(100,0,0,0,0,0,0);
  }
  return;
}

