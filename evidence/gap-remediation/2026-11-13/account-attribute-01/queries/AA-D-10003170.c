
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_10003170(uint param_1)

{
  bool bVar1;
  undefined *puVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  byte *pbVar7;
  char cVar8;
  uint uVar9;
  byte bVar10;
  int iVar11;
  undefined1 auStack_6d0 [128];
  undefined1 auStack_5fc [4];
  int local_5f8;
  byte local_5f0;
  byte local_5ef [51];
  undefined1 *local_5bc;
  undefined1 local_5b8;
  undefined1 auStack_5b7 [51];
  undefined1 *local_584;
  byte local_580;
  undefined1 auStack_57f [103];
  undefined1 local_518;
  undefined1 auStack_517 [511];
  undefined1 auStack_318 [700];
  ushort local_5c;
  undefined1 auStack_5a [50];
  
  puVar2 = PTR_DAT_10088d8c;
  if ((*(int *)(param_1 + 0x18) == 0) || (*(short *)(param_1 + 0xa2) == 0)) {
    FUN_100578e0();
  }
  else {
    iVar11 = *(int *)(PTR_DAT_10088d8c + 0x20);
    _DAT_10096074 = _DAT_10096074 + *(int *)(PTR_DAT_10088d8c + 0x1c);
    local_584 = auStack_6d0 + 0x80;
    iVar3 = FUN_10028fc0();
    if (iVar3 != 0) {
      iVar4 = FUN_1002c4d0(iVar3,1);
      iVar5 = FUN_10052c50((iVar4 - iVar11) + -0x20,1);
      uVar6 = FUN_10053290();
      FUN_1002c220(iVar3,1);
      FUN_1002c3b0(iVar3,iVar11 + 0x20,uVar6,(iVar4 - iVar11) + -0x20,0);
      local_5f8 = FUN_10078210(uVar6,(iVar4 - iVar11) + -0x20,auStack_5fc);
      for (bVar10 = 0; bVar10 < 3; bVar10 = bVar10 + 1) {
        _DAT_10096074 =
             (_DAT_10096074 - *(int *)(puVar2 + (uint)bVar10 * 4 + 0x10)) +
             *(int *)(local_5f8 + (uint)bVar10 * 4);
      }
      _DAT_10096074 = _DAT_10096074 - *(int *)(local_5f8 + 0xc);
      if (local_5f8 != 0) {
        FUN_10052c10(local_5f8);
      }
      FUN_1002c2c0(iVar3);
      FUN_10053310(iVar5);
      if (iVar5 != 0) {
        FUN_10052e90(iVar5);
      }
      if (iVar3 != 0) {
        FUN_1002b2f0(iVar3);
      }
    }
    if (((_DAT_10096074 & 3) != 0) || (_DAT_10096074 >> 0x10 != param_1 >> 0x10)) {
      FUN_10027c30(1,1);
    }
    local_5bc = auStack_6d0 + 0x80;
    FUN_100073c0(param_1,param_1 + 0x16c,auStack_318);
    if (0x1f < local_5c) {
      local_5c = 0x1f;
    }
    local_5f0 = FUN_100539c0(local_5ef,auStack_5a,local_5c);
    uVar9 = (uint)local_5f0;
    pbVar7 = local_5ef;
    while (bVar1 = uVar9 != 0, uVar9 = uVar9 - 1, bVar1) {
      *pbVar7 = ~*pbVar7;
      pbVar7 = pbVar7 + 1;
    }
    cVar8 = FUN_1006e2b0(0x1008fbde);
    if (cVar8 == '\0') {
      cVar8 = FUN_100021e0(param_1);
      if (cVar8 != '\0') {
        FUN_1006e2e0(s_hotline_http___www_BigRedH_com_d_1008fbdf + 8,
                     s_hotline_http___www_BigRedH_com_d_1008fbdf[7],0,0);
      }
    }
    else {
      uVar6 = FUN_10058270(*(undefined4 *)(param_1 + 0x18));
      local_5b8 = FUN_1006d5e0(uVar6,auStack_5b7,0x1f);
      FUN_100539c0(&local_580,param_1 + 0x16c,*(byte *)(param_1 + 0x16c) + 1);
      if (local_5f0 != 0) {
        cVar8 = FUN_100539c0(auStack_57f + local_580,
                             s_hotline_http___www_BigRedH_com_d_1008fbdf + 0x28,1);
        local_580 = local_580 + cVar8;
        cVar8 = FUN_100539c0(auStack_57f + local_580,local_5ef,local_5f0);
        local_580 = local_580 + cVar8;
      }
      local_518 = FUN_10054180(auStack_517,0xff,s_hotline_____s___s__lu_1008fc09,&local_580,
                               &local_5b8,*(undefined2 *)(param_1 + 0xa2));
      cVar8 = FUN_1006e2e0(auStack_517,local_518,0,0);
      if ((cVar8 == '\0') && (cVar8 = FUN_100021e0(param_1), cVar8 != '\0')) {
        FUN_1006e2e0(s_hotline_http___www_BigRedH_com_d_1008fbdf + 8,
                     s_hotline_http___www_BigRedH_com_d_1008fbdf[7],0,0);
      }
    }
  }
  return;
}

