
/* WARNING: Removing unreachable block (ram,0x1000de98) */

void FUN_1000dc60(int param_1)

{
  ushort uVar1;
  bool bVar2;
  int iVar3;
  char cVar6;
  undefined4 uVar4;
  int iVar5;
  ushort *puVar7;
  uint uVar8;
  uint uVar9;
  int iVar10;
  undefined1 auStack_140 [128];
  char local_80 [4];
  int *local_7c;
  uint local_78;
  ushort *local_74;
  undefined4 local_70;
  undefined2 *local_6c;
  undefined4 local_68;
  int local_64 [6];
  undefined1 *local_4c;
  undefined1 *local_34;
  
  local_7c = (int *)0x0;
  iVar3 = FUN_10057d00();
  uVar9 = 0;
LAB_1000e5a8:
  do {
    uVar8 = uVar9;
    uVar9 = uVar8 + 1;
    if (*(uint *)(param_1 + 0x78) < uVar9) {
      return;
    }
    local_7c = *(int **)(*(int *)(param_1 + 0x74) + uVar9 * 4 + -4);
    iVar10 = *local_7c;
    cVar6 = FUN_10055af0(param_1 + 0x34,local_7c[0xc]);
    if (cVar6 == '\0') goto LAB_1000dda4;
    if (iVar10 != 0) break;
    if (500 < (uint)(iVar3 - local_7c[4])) {
      FUN_10055630(param_1 + 0x74,local_7c);
      FUN_1002b2f0(local_7c[1]);
      FUN_1006d290(local_7c);
      FUN_10006860(param_1,s_Upload_aborted__no_response__100904a7);
      if (*(uint *)(param_1 + 0x42c) < *(uint *)(param_1 + 0x428)) {
        *(undefined4 *)(param_1 + 0x42c) = *(undefined4 *)(param_1 + 0x428);
      }
      uVar9 = uVar8;
      if (*(int *)(param_1 + 0x8c) != 0) {
        FUN_10021940(*(undefined4 *)(param_1 + 0x8c),*(undefined4 *)(param_1 + 0x428),
                     *(int *)(param_1 + 0x3c) + *(int *)(param_1 + 0x48),
                     *(int *)(param_1 + 0x6c) + *(int *)(param_1 + 0x78),
                     *(undefined4 *)(param_1 + 0x54),*(undefined4 *)(param_1 + 0x42c),
                     *(undefined4 *)(param_1 + 0x430),*(undefined4 *)(param_1 + 0x434));
      }
    }
  } while( true );
  cVar6 = FUN_1006da10(iVar10);
  if ((cVar6 != '\0') && ((uint)(iVar3 - local_7c[4]) < 0x79)) {
    do {
      while( true ) {
        uVar1 = *(ushort *)((int)local_7c + 0x36);
        if (uVar1 == 2) break;
        if (uVar1 < 2) {
          if (uVar1 == 0) {
            local_78 = CONCAT22(3,local_78._2_2_);
            FUN_1006de90(iVar10,&local_78,2);
            *(short *)((int)local_7c + 0x36) = *(short *)((int)local_7c + 0x36) + 1;
            goto LAB_1000e5a8;
          }
          cVar6 = FUN_1006e120(iVar10,2);
          if (cVar6 == '\0') goto LAB_1000e5a8;
          FUN_1006dfb0(iVar10,&local_78,2);
          local_7c[0xb] = local_78 >> 0x10;
          *(short *)((int)local_7c + 0x36) = *(short *)((int)local_7c + 0x36) + 1;
        }
        else {
          if (uVar1 == 4) goto LAB_1000e438;
          if ((3 < uVar1) || (cVar6 = FUN_1006e120(iVar10,4), cVar6 == '\0')) goto LAB_1000e5a8;
          FUN_1006dfb0(iVar10,&local_78,4);
          local_7c[9] = local_78;
          local_7c[10] = 0;
          *(short *)((int)local_7c + 0x36) = *(short *)((int)local_7c + 0x36) + 1;
        }
      }
      cVar6 = FUN_1006e120(iVar10,local_7c[0xb]);
      if (cVar6 == '\0') goto LAB_1000e5a8;
      local_74 = (ushort *)FUN_10052a10(local_7c[0xb]);
      FUN_1006dfb0(iVar10,local_74,local_7c[0xb]);
      uVar1 = *local_74;
      local_7c[2] = 0;
      bVar2 = false;
      puVar7 = local_74 + 1;
      local_4c = auStack_140 + 0x80;
      uVar4 = FUN_1006e960(puVar7,local_7c[0xb] + -2);
      iVar5 = FUN_1002b0e0(local_7c[1],puVar7,uVar4,0,0,0);
      local_7c[2] = iVar5;
      if ((uVar1 & 1) == 0) {
        cVar6 = FUN_1000ecc0(param_1,local_7c[2]);
        if (cVar6 == '\0') {
          cVar6 = FUN_1002b750(local_7c[2],0);
          if (cVar6 == '\0') {
            FUN_1002b370(local_7c[2],0x48546674,0x48544c43);
            FUN_1002d9e0(local_7c[2]);
            local_78 = CONCAT22(1,local_78._2_2_);
            FUN_1006de90(iVar10,&local_78,2);
            *(undefined2 *)((int)local_7c + 0x36) = 3;
          }
          else {
            iVar5 = FUN_1002c4d0(local_7c[2],0);
            local_7c[6] = local_7c[6] - iVar5;
          }
        }
        else {
          iVar5 = FUN_1002c4d0(local_7c[2],0);
          local_7c[6] = local_7c[6] - iVar5;
          uVar4 = FUN_1002db60(local_7c[2]);
          iVar5 = FUN_10052f80();
          local_70 = uVar4;
          uVar4 = FUN_10053290(uVar4);
          local_6c = (undefined2 *)FUN_10052a10(iVar5 + 4);
          *local_6c = 2;
          local_6c[1] = (short)iVar5;
          FUN_100539c0(local_6c + 2,uVar4,iVar5);
          FUN_1006de90(iVar10,local_6c,iVar5 + 4);
          *(undefined2 *)((int)local_7c + 0x36) = 3;
          FUN_10052c10(local_6c);
          FUN_10053310(local_70);
        }
      }
      else {
        cVar6 = FUN_1002b750(local_7c[2],local_80);
        if (cVar6 == '\0') {
          FUN_1002b670(local_7c[2]);
        }
        else if (local_80[0] == '\0') {
          bVar2 = true;
        }
      }
      if ((bVar2) || (*(short *)((int)local_7c + 0x36) == 2)) {
        FUN_1002b2f0(local_7c[2]);
        local_7c[2] = 0;
        local_78 = CONCAT22(3,local_78._2_2_);
        FUN_1006de90(iVar10,&local_78,2);
        iVar5 = local_7c[8];
        local_7c[8] = iVar5 + 1;
        if (iVar5 + 1 == local_7c[7]) {
          if (bVar2) {
            FUN_100069b0(param_1,iVar10,s_Upload_folder_item_failed_100904e3);
          }
          else {
            FUN_100069b0(param_1,iVar10,s_Upload_folder_complete_100904fd);
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
          FUN_10055630(param_1 + 0x74,local_7c);
          FUN_1006daf0(iVar10);
          FUN_1002b2f0(local_7c[1]);
          FUN_1006d3e0(iVar10);
          FUN_1006d290(local_7c);
          FUN_10052c10(local_74);
          uVar9 = uVar8;
          goto LAB_1000e5a8;
        }
        *(undefined2 *)((int)local_7c + 0x36) = 1;
      }
      local_7c[0xb] = 0;
      FUN_10052c10(local_74);
    } while( true );
  }
LAB_1000dda4:
  FUN_100069b0(param_1,iVar10,s_Upload_aborted_100904c4);
  FUN_10055630(param_1 + 0x74,local_7c);
  FUN_1006d3e0(iVar10);
  FUN_1002b2f0(local_7c[1]);
  if (local_7c[2] != 0) {
    FUN_1002b2f0(local_7c[2]);
  }
  FUN_1006d290(local_7c);
  if (*(uint *)(param_1 + 0x42c) < *(uint *)(param_1 + 0x428)) {
    *(undefined4 *)(param_1 + 0x42c) = *(undefined4 *)(param_1 + 0x428);
  }
  uVar9 = uVar8;
  if (*(int *)(param_1 + 0x8c) != 0) {
    FUN_10021940(*(undefined4 *)(param_1 + 0x8c),*(undefined4 *)(param_1 + 0x428),
                 *(int *)(param_1 + 0x3c) + *(int *)(param_1 + 0x48),
                 *(int *)(param_1 + 0x6c) + *(int *)(param_1 + 0x78),*(undefined4 *)(param_1 + 0x54)
                 ,*(undefined4 *)(param_1 + 0x42c),*(undefined4 *)(param_1 + 0x430),
                 *(undefined4 *)(param_1 + 0x434));
  }
  goto LAB_1000e5a8;
LAB_1000e438:
  while (cVar6 = FUN_1006df20(iVar10,&local_68,local_64), cVar6 != '\0') {
    local_34 = auStack_140 + 0x80;
    FUN_1002ddf0(local_7c[2],local_68,local_64[0]);
    local_7c[10] = local_7c[10] + local_64[0];
    local_7c[5] = local_7c[5] + local_64[0];
    local_7c[4] = iVar3;
    FUN_1006dde0(local_68);
  }
  if ((uint)local_7c[9] <= (uint)local_7c[10]) {
    FUN_1002ddf0(local_7c[2],0,0);
    FUN_1002b2f0(local_7c[2]);
    local_7c[2] = 0;
    iVar5 = local_7c[8];
    local_7c[8] = iVar5 + 1;
    if (iVar5 + 1 == local_7c[7]) {
      FUN_100069b0(param_1,iVar10,s_Upload_folder_complete_100904fd);
      FUN_10055630(param_1 + 0x74,local_7c);
      FUN_1006daf0(iVar10);
      FUN_1002b2f0(local_7c[1]);
      FUN_1006d3e0(iVar10);
      FUN_1006d290(local_7c);
      if (*(uint *)(param_1 + 0x42c) < *(uint *)(param_1 + 0x428)) {
        *(undefined4 *)(param_1 + 0x42c) = *(undefined4 *)(param_1 + 0x428);
      }
      uVar9 = uVar8;
      if (*(int *)(param_1 + 0x8c) != 0) {
        FUN_10021940(*(undefined4 *)(param_1 + 0x8c),*(undefined4 *)(param_1 + 0x428),
                     *(int *)(param_1 + 0x3c) + *(int *)(param_1 + 0x48),
                     *(int *)(param_1 + 0x6c) + *(int *)(param_1 + 0x78),
                     *(undefined4 *)(param_1 + 0x54),*(undefined4 *)(param_1 + 0x42c),
                     *(undefined4 *)(param_1 + 0x430),*(undefined4 *)(param_1 + 0x434));
      }
    }
    else {
      *(undefined2 *)((int)local_7c + 0x36) = 1;
      local_78 = CONCAT22(3,local_78._2_2_);
      FUN_1006de90(iVar10,&local_78,2);
    }
  }
  goto LAB_1000e5a8;
}

