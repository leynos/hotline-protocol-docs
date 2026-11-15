
/* WARNING: Removing unreachable block (ram,0x1000c8f4) */

void FUN_1000c6a0(int param_1)

{
  undefined1 *puVar1;
  byte bVar2;
  ushort uVar3;
  int iVar4;
  char cVar8;
  int iVar5;
  uint uVar6;
  undefined4 uVar7;
  byte *pbVar9;
  uint uVar10;
  uint uVar11;
  int iVar12;
  undefined1 auStack_530 [128];
  byte local_470 [2];
  short local_46e;
  short local_46c [2];
  int *local_468;
  int local_464;
  byte *local_460;
  undefined4 local_45c;
  undefined1 *local_444;
  undefined1 *local_42c;
  byte abStack_28 [4];
  undefined1 auStack_24 [2];
  undefined1 auStack_22 [2];
  
  puVar1 = auStack_530 + 0x80;
  local_468 = (int *)0x0;
  iVar4 = FUN_10057d00();
  uVar11 = 0;
LAB_1000ceec:
  do {
    uVar10 = uVar11;
    uVar11 = uVar10 + 1;
    if (*(uint *)(param_1 + 0x48) < uVar11) {
      return;
    }
    local_468 = *(int **)(*(int *)(param_1 + 0x44) + uVar11 * 4 + -4);
    iVar12 = *local_468;
    cVar8 = FUN_10055af0(param_1 + 0x34,local_468[0xb]);
    if (cVar8 == '\0') goto LAB_1000c7ec;
    if (iVar12 != 0) break;
    iVar12 = FUN_10057d00();
    if (500 < (uint)(iVar12 - local_468[4])) {
      FUN_10055630(param_1 + 0x44,local_468);
      if (local_468[1] != 0) {
        FUN_10026670(local_468[1],1);
      }
      FUN_1006d290(local_468);
      FUN_10006860(param_1,s_Download_aborted__no_response__1009041c);
      if (*(uint *)(param_1 + 0x42c) < *(uint *)(param_1 + 0x428)) {
        *(undefined4 *)(param_1 + 0x42c) = *(undefined4 *)(param_1 + 0x428);
      }
      uVar11 = uVar10;
      if (*(int *)(param_1 + 0x8c) != 0) {
        FUN_10021940(*(undefined4 *)(param_1 + 0x8c),*(undefined4 *)(param_1 + 0x428),
                     *(int *)(param_1 + 0x3c) + *(int *)(param_1 + 0x48),
                     *(int *)(param_1 + 0x6c) + *(int *)(param_1 + 0x78),
                     *(undefined4 *)(param_1 + 0x54),*(undefined4 *)(param_1 + 0x42c),
                     *(undefined4 *)(param_1 + 0x430),*(undefined4 *)(param_1 + 0x434));
      }
    }
  } while( true );
  cVar8 = FUN_1006da10(iVar12);
  if (cVar8 != '\0') {
    do {
      while( true ) {
        while( true ) {
          uVar3 = *(ushort *)(local_468 + 0xd);
          if (uVar3 != 2) break;
          local_444 = puVar1;
          if ((local_468[2] == 0) ||
             ((uVar6 = FUN_1006e040(iVar12), (uint)local_468[9] < uVar6 &&
              (cVar8 = FUN_1006e1a0(iVar12), cVar8 == '\0')))) goto LAB_1000ceec;
          if ((uint)local_468[7] < 0x19000) {
            if ((uint)local_468[9] < (uint)local_468[7]) {
              local_468[9] = local_468[7];
            }
          }
          else {
            if (uVar6 == 0) {
              local_468[9] = local_468[9] + 0x19000;
            }
            if ((uint)(iVar4 - local_468[10]) < 10) {
              local_468[9] = local_468[9] + 0x19000;
            }
            local_468[10] = iVar4;
          }
          if (0x200000 < (uint)local_468[9]) {
            local_468[9] = 0x200000;
          }
          uVar6 = local_468[9];
          if ((uint)(local_468[7] - local_468[8]) < (uint)local_468[9]) {
            uVar6 = local_468[7] - local_468[8];
          }
          uVar7 = FUN_1006ddb0(uVar6);
          local_42c = puVar1;
          FUN_1002d830(local_468[2],uVar7,uVar6);
          FUN_1006de10(iVar12,uVar7);
          local_468[8] = local_468[8] + uVar6;
          local_468[6] = local_468[6] + uVar6;
          FUN_1006e0b0(iVar12);
          if ((uint)local_468[8] < (uint)local_468[7]) goto LAB_1000ceec;
          FUN_1002b2f0(local_468[2]);
          local_468[2] = 0;
          local_468[7] = 0;
          local_468[8] = 0;
          *(undefined2 *)(local_468 + 0xd) = 0;
        }
        if (uVar3 < 2) break;
        if (uVar3 == 0xb) {
          cVar8 = FUN_1006e120(iVar12,*(undefined2 *)((int)local_468 + 0x36));
          if (cVar8 == '\0') goto LAB_1000ceec;
          local_45c = FUN_10052a10(*(undefined2 *)((int)local_468 + 0x36));
          uVar7 = FUN_1006dfb0(iVar12,local_45c,*(undefined2 *)((int)local_468 + 0x36));
          FUN_1002d650(local_468[2],local_45c,uVar7);
          FUN_10052c10(local_45c);
LAB_1000cb3c:
          iVar5 = FUN_1002d7b0(local_468[2]);
          local_468[7] = iVar5;
          iVar5 = FUN_1002c4d0(local_468[2],0);
          local_468[5] = local_468[5] - (iVar5 - local_468[7]);
          local_464 = local_468[7];
          FUN_1006de90(*local_468,&local_464,4);
          *(undefined2 *)(local_468 + 0xd) = 2;
        }
        else {
          if (((10 < uVar3) || (uVar3 < 10)) || (cVar8 = FUN_1006e120(iVar12,2), cVar8 == '\0'))
          goto LAB_1000ceec;
          FUN_1006dfb0(iVar12,&local_464,2);
          *(short *)((int)local_468 + 0x36) = local_464._0_2_;
          *(short *)(local_468 + 0xd) = *(short *)(local_468 + 0xd) + 1;
        }
      }
      if (uVar3 == 0) {
        cVar8 = FUN_1006e120(iVar12,2);
        if (cVar8 != '\0') {
          FUN_1006dfb0(iVar12,&local_464,2);
          if (local_464._0_2_ == 3) goto LAB_1000c948;
        }
        goto LAB_1000ceec;
      }
      cVar8 = FUN_1006e120(iVar12,2);
      if (cVar8 == '\0') goto LAB_1000ceec;
      FUN_1006dfb0(iVar12,&local_464,2);
      if (local_464._0_2_ == 3) {
        iVar5 = FUN_1002c4d0(local_468[2],0);
        local_468[5] = local_468[5] - iVar5;
        goto LAB_1000c948;
      }
      if (local_464._0_2_ == 1) {
        FUN_1002d470(local_468[2]);
        goto LAB_1000cb3c;
      }
      if (local_464._0_2_ != 2) goto LAB_1000ceec;
      *(undefined2 *)(local_468 + 0xd) = 10;
    } while( true );
  }
LAB_1000c7ec:
  FUN_100069b0(param_1,iVar12,s_Download_connection_closed_1009043b);
  FUN_10055630(param_1 + 0x44,local_468);
  if (local_468[1] != 0) {
    FUN_10026670(local_468[1],1);
  }
  if (local_468[2] != 0) {
    FUN_1002b2f0(local_468[2]);
  }
  FUN_1006d3e0(iVar12);
  FUN_1006d290(local_468);
  if (*(uint *)(param_1 + 0x42c) < *(uint *)(param_1 + 0x428)) {
    *(undefined4 *)(param_1 + 0x42c) = *(undefined4 *)(param_1 + 0x428);
  }
  uVar11 = uVar10;
  if (*(int *)(param_1 + 0x8c) != 0) {
    FUN_10021940(*(undefined4 *)(param_1 + 0x8c),*(undefined4 *)(param_1 + 0x428),
                 *(int *)(param_1 + 0x3c) + *(int *)(param_1 + 0x48),
                 *(int *)(param_1 + 0x6c) + *(int *)(param_1 + 0x78),*(undefined4 *)(param_1 + 0x54)
                 ,*(undefined4 *)(param_1 + 0x42c),*(undefined4 *)(param_1 + 0x430),
                 *(undefined4 *)(param_1 + 0x434));
  }
  goto LAB_1000ceec;
  while (local_46e < 6) {
LAB_1000c948:
    local_46e = 0x400;
    local_460 = abStack_28;
    local_46c[0] = 0;
    local_470[0] = 0;
    iVar5 = FUN_100273a0(local_468[1],&local_460,&local_46e,local_46c,local_470);
    if (iVar5 == 0) {
      FUN_10055630(param_1 + 0x44,local_468);
      if (local_468[1] != 0) {
        FUN_10026670(local_468[1],1);
      }
      FUN_1006d290(local_468);
      FUN_1006d3e0(iVar12);
      uVar11 = uVar10;
      goto LAB_1000ceec;
    }
  }
  if (local_468[2] != 0) {
    FUN_1002b2f0(local_468[2]);
  }
  iVar5 = FUN_1002b250(iVar5);
  local_468[2] = iVar5;
  pbVar9 = local_460 + 2;
  bVar2 = *pbVar9;
  local_46c[0] = local_46c[0] + -1;
  *(short *)(pbVar9 + (bVar2 - 1)) = local_46c[0];
  *(ushort *)(pbVar9 + (bVar2 - 3)) = (ushort)local_470[0];
  local_460 = pbVar9 + (bVar2 - 5);
  *(short *)local_460 = (short)auStack_24 + (short)-(int)(pbVar9 + bVar2 + 1);
  FUN_1006de90(iVar12,local_460,auStack_22 + -(int)(pbVar9 + bVar2 + 1));
  *(ushort *)(local_468 + 0xd) = (ushort)(local_470[0] == 0);
  goto LAB_1000ceec;
}

