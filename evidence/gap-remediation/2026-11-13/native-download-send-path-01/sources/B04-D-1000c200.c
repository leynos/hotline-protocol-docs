
void FUN_1000c200(int param_1)

{
  int *piVar1;
  int iVar2;
  char cVar6;
  uint uVar3;
  undefined4 uVar4;
  uint uVar5;
  uint uVar7;
  int iVar8;
  
  iVar2 = FUN_10057d00();
  uVar7 = 0;
  do {
    while( true ) {
      uVar3 = uVar7;
      uVar7 = uVar3 + 1;
      if (*(uint *)(param_1 + 0x3c) < uVar7) {
        return;
      }
      piVar1 = *(int **)(*(int *)(param_1 + 0x38) + uVar7 * 4 + -4);
      iVar8 = *piVar1;
      cVar6 = FUN_10055af0(param_1 + 0x34,piVar1[9]);
      if (cVar6 != '\0') break;
LAB_1000c338:
      FUN_100069b0(param_1,iVar8,s_Download_connection_closed_1009043b);
      FUN_10055630(param_1 + 0x38,piVar1);
      FUN_1002b2f0(piVar1[1]);
      FUN_1006d3e0(iVar8);
      FUN_1006d290(piVar1);
      if (*(uint *)(param_1 + 0x42c) < *(uint *)(param_1 + 0x428)) {
        *(undefined4 *)(param_1 + 0x42c) = *(undefined4 *)(param_1 + 0x428);
      }
      uVar7 = uVar3;
      if (*(int *)(param_1 + 0x8c) != 0) {
        FUN_10021940(*(undefined4 *)(param_1 + 0x8c),*(undefined4 *)(param_1 + 0x428),
                     *(int *)(param_1 + 0x3c) + *(int *)(param_1 + 0x48),
                     *(int *)(param_1 + 0x6c) + *(int *)(param_1 + 0x78),
                     *(undefined4 *)(param_1 + 0x54),*(undefined4 *)(param_1 + 0x42c),
                     *(undefined4 *)(param_1 + 0x430),*(undefined4 *)(param_1 + 0x434));
      }
    }
    if (iVar8 == 0) {
      iVar8 = FUN_10057d00();
      if (500 < (uint)(iVar8 - piVar1[3])) {
        FUN_10055630(param_1 + 0x38,piVar1);
        FUN_1002b2f0(piVar1[1]);
        FUN_1006d290(piVar1);
        FUN_10006860(param_1,s_Download_aborted__no_response__1009041c);
        if (*(uint *)(param_1 + 0x42c) < *(uint *)(param_1 + 0x428)) {
          *(undefined4 *)(param_1 + 0x42c) = *(undefined4 *)(param_1 + 0x428);
        }
        uVar7 = uVar3;
        if (*(int *)(param_1 + 0x8c) != 0) {
          FUN_10021940(*(undefined4 *)(param_1 + 0x8c),*(undefined4 *)(param_1 + 0x428),
                       *(int *)(param_1 + 0x3c) + *(int *)(param_1 + 0x48),
                       *(int *)(param_1 + 0x6c) + *(int *)(param_1 + 0x78),
                       *(undefined4 *)(param_1 + 0x54),*(undefined4 *)(param_1 + 0x42c),
                       *(undefined4 *)(param_1 + 0x430),*(undefined4 *)(param_1 + 0x434));
        }
      }
    }
    else {
      cVar6 = FUN_1006da10(iVar8);
      if (cVar6 == '\0') goto LAB_1000c338;
      if ((piVar1[1] != 0) &&
         ((uVar3 = FUN_1006e040(iVar8), uVar3 <= (uint)piVar1[7] ||
          (cVar6 = FUN_1006e1a0(iVar8), cVar6 != '\0')))) {
        if (uVar3 == 0) {
          piVar1[7] = piVar1[7] + 0x19000;
        }
        if ((uint)(iVar2 - piVar1[8]) < 10) {
          piVar1[7] = piVar1[7] + 0x19000;
        }
        piVar1[8] = iVar2;
        if (0x200000 < (uint)piVar1[7]) {
          piVar1[7] = 0x200000;
        }
        uVar3 = piVar1[7];
        if ((uint)(piVar1[5] - piVar1[6]) < (uint)piVar1[7]) {
          uVar3 = piVar1[5] - piVar1[6];
        }
        uVar4 = FUN_1006ddb0(uVar3);
        if (*(char *)((int)piVar1 + 0x2a) == '\0') {
          FUN_1002d830(piVar1[1],uVar4,uVar3);
        }
        else {
          uVar5 = FUN_1002c3b0(piVar1[1],piVar1[4],uVar4,uVar3,0);
          if (uVar3 != uVar5) {
            FUN_10027c30(1,1);
          }
          piVar1[4] = piVar1[4] + uVar3;
        }
        FUN_1006de10(iVar8,uVar4);
        piVar1[6] = piVar1[6] + uVar3;
        FUN_1006e0b0(iVar8);
        if ((uint)piVar1[5] <= (uint)piVar1[6]) {
          FUN_1002b2f0(piVar1[1]);
          piVar1[1] = 0;
          FUN_100069b0(param_1,iVar8,s_Download_complete_10090456);
        }
      }
    }
  } while( true );
}

