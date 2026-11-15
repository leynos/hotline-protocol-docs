
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

undefined4 FUN_100023a0(uint param_1)

{
  bool bVar1;
  bool bVar2;
  char cVar10;
  undefined4 uVar3;
  undefined4 *puVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined4 *puVar8;
  short sVar9;
  undefined1 uVar11;
  uint uVar12;
  undefined1 *puVar13;
  byte bVar14;
  undefined1 auStack_5c0 [128];
  undefined1 auStack_4fc [4];
  undefined1 auStack_4f8 [4];
  int local_4f4;
  undefined1 auStack_4f0 [4];
  undefined1 auStack_4ec [4];
  undefined1 auStack_4e8 [4];
  undefined1 auStack_4e4 [4];
  undefined1 auStack_4e0 [4];
  undefined1 auStack_4dc [4];
  int local_4d8;
  uint local_4d4;
  undefined1 local_4c8;
  undefined1 auStack_4c7 [31];
  int local_4a8;
  undefined4 local_4a4;
  undefined4 local_4a0;
  undefined4 local_49c;
  uint local_498;
  undefined1 *local_47c;
  undefined1 local_478;
  undefined1 auStack_477 [127];
  undefined **local_3f8 [3];
  undefined4 local_3ec;
  undefined4 local_398;
  int local_380 [5];
  int local_36c [13];
  undefined1 local_338;
  undefined1 auStack_337 [255];
  undefined1 local_238;
  undefined1 auStack_237 [255];
  undefined1 local_138;
  undefined1 auStack_137 [267];
  
  cVar10 = FUN_1000ee70();
  if (cVar10 == '\0') {
    puVar4 = (undefined4 *)FUN_100014c0();
    iVar5 = FUN_100014b0(puVar4[8]);
    local_47c = auStack_5c0 + 0x80;
    iVar6 = FUN_100014b0(*puVar4);
    _DAT_10096074 = _DAT_10096074 - iVar6;
    iVar6 = FUN_100014b0(puVar4[7]);
    _DAT_10096074 = _DAT_10096074 + iVar6;
    iVar6 = FUN_10028fc0();
    if (iVar6 != 0) {
      FUN_100014a0(auStack_4fc,iVar6);
      iVar7 = FUN_10001470(iVar6,1);
      uVar3 = FUN_10052c50(iVar7,1);
      FUN_10001460(auStack_4f8,uVar3);
      FUN_10001410(auStack_4f0,uVar3,&local_4f4);
      FUN_100013d0(auStack_4ec,iVar6,1);
      FUN_100013a0(iVar6,0,local_4f4,iVar7,0);
      puVar8 = (undefined4 *)FUN_10078210(local_4f4,iVar5,auStack_4e8);
      FUN_10001390(auStack_4e4,puVar8);
      iVar6 = FUN_100014b0(*puVar8);
      _DAT_10096074 = _DAT_10096074 + iVar6;
      for (bVar14 = 1; bVar14 < 4; bVar14 = bVar14 + 1) {
        iVar6 = FUN_100014b0(puVar4[bVar14]);
        _DAT_10096074 = _DAT_10096074 + iVar6;
        iVar6 = FUN_100014b0(puVar8[bVar14]);
        _DAT_10096074 = _DAT_10096074 - iVar6;
      }
      iVar5 = FUN_10078210(local_4f4 + iVar5 + 0x20,(iVar7 - iVar5) + -0x20,auStack_4e0);
      FUN_10001390(auStack_4dc,iVar5);
      for (bVar14 = 0; bVar14 < 3; bVar14 = bVar14 + 1) {
        iVar6 = FUN_100014b0(puVar4[bVar14 + 4]);
        _DAT_10096074 = _DAT_10096074 - iVar6;
        iVar6 = FUN_100014b0(*(undefined4 *)(iVar5 + (uint)bVar14 * 4));
        _DAT_10096074 = _DAT_10096074 + iVar6;
      }
      iVar5 = FUN_100014b0(*(undefined4 *)(iVar5 + 0xc));
      _DAT_10096074 = _DAT_10096074 - iVar5;
      FUN_10001320(auStack_4dc,0xffffffff);
      FUN_10001320(auStack_4e4,0xffffffff);
      FUN_100012c0(auStack_4ec,0xffffffff);
      FUN_10001260(auStack_4f0,0xffffffff);
      FUN_100011f0(auStack_4f8,0xffffffff);
      FUN_10001180(auStack_4fc,0xffffffff);
    }
    if (((_DAT_10096074 & 3) != 0) || (_DAT_10096074 >> 0x10 != param_1 >> 0x10)) {
      FUN_10027c30(1,1);
    }
    FUN_1001b4a0(local_3f8);
    bVar1 = false;
    cVar10 = FUN_1006eaa0();
    if (cVar10 == '\0') {
      *(uint *)(param_1 + 0xac) = *(uint *)(param_1 + 0xac) & 0xffffffef;
    }
    else {
      *(uint *)(param_1 + 0xac) = *(uint *)(param_1 + 0xac) | 0x10;
    }
    FUN_10055460(&local_4d8);
    FUN_1000a070(param_1,&local_4d8);
    FUN_1001ddb0(local_3f8,param_1 + 0xcc,param_1 + 0xec,param_1 + 0x16c,param_1 + 0x18c,
                 param_1 + 0x20c,param_1 + 0x30c,&local_4d8);
    if ((*(byte *)(param_1 + 200) >> 6 & 1) != 0) {
      FUN_10082630(local_398,0);
    }
    for (uVar12 = 0; uVar12 < 5; uVar12 = uVar12 + 1) {
      puVar13 = (undefined1 *)(param_1 + uVar12 * 0x144 + 0x45c);
      FUN_100691c0(local_380[uVar12],puVar13 + 1,*puVar13);
      puVar13 = (undefined1 *)(param_1 + uVar12 * 0x144 + 0x57c);
      FUN_1006c050(local_36c[uVar12],puVar13 + 1,*puVar13);
    }
    uVar12 = 0;
    while (uVar12 = uVar12 + 1, uVar12 <= local_4d4) {
      FUN_1006d290(*(undefined4 *)(local_4d8 + uVar12 * 4 + -4));
    }
    FUN_10055880(&local_4d8);
    FUN_1003a510(local_3ec,1);
    while( true ) {
      FUN_100370f0(local_3f8);
      iVar5 = FUN_100375d0(local_3f8);
      if ((iVar5 == 1) || (iVar5 == 3)) break;
      if (iVar5 == 2) {
        FUN_10055480(&local_4d8,0);
        local_3f8[0] = &PTR_PTR_1008f480;
        FUN_10036850(local_3f8,0);
        return 0;
      }
      if ((iVar5 == 4) || (iVar5 == 5)) {
        FUN_1001e600(local_3f8);
      }
      else if (iVar5 == 6) {
        FUN_1001e810(local_3f8);
      }
      else if (iVar5 == 7) {
        FUN_1001e870(local_3f8);
      }
      else if (iVar5 == 8) {
        FUN_1001e7a0(local_3f8,&local_338);
        cVar10 = FUN_10008210(param_1,&local_338);
        if (cVar10 != '\0') {
          FUN_1001e730(local_3f8,&local_338);
        }
      }
      else if (iVar5 == 9) {
        FUN_1001e7a0(local_3f8,&local_338);
        cVar10 = FUN_100089a0(param_1,&local_338);
        if (cVar10 != '\0') {
          FUN_1001e730(local_3f8,&local_338);
        }
        FUN_10008850(param_1,&local_338);
      }
    }
    FUN_1001e7a0(local_3f8,&local_4c8);
    cVar10 = FUN_100089a0(param_1,&local_4c8);
    if (cVar10 != '\0') {
      FUN_1001e730(local_3f8,&local_4c8);
    }
    FUN_100539c0(&local_4c8,param_1 + 0x16c,*(byte *)(param_1 + 0x16c) + 1);
    uVar12 = *(uint *)(param_1 + 0xac) >> 7 & 1;
    FUN_100539c0(&local_478,param_1 + 0x18c,*(byte *)(param_1 + 0x18c) + 1);
    FUN_100539c0(&local_238,param_1 + 0x20c,*(byte *)(param_1 + 0x20c) + 1);
    FUN_100539c0(&local_138,param_1 + 0x30c,*(byte *)(param_1 + 0x30c) + 1);
    local_4a8 = *(int *)(param_1 + 0x9c);
    local_4a4 = *(undefined4 *)(param_1 + 0xa0);
    local_4a0 = *(undefined4 *)(param_1 + 0xa4);
    local_49c = *(undefined4 *)(param_1 + 0xa8);
    local_498 = *(uint *)(param_1 + 0xac);
    FUN_1001e170(local_3f8,param_1 + 0xcc,param_1 + 0xec,param_1 + 0x16c,param_1 + 0x18c,
                 param_1 + 0x20c,param_1 + 0x30c,&local_4d8);
    bVar2 = false;
    if ((local_4a8 != *(int *)(param_1 + 0x9c)) || (local_4a4._0_2_ != *(short *)(param_1 + 0xa0)))
    {
      bVar2 = true;
      *(int *)(param_1 + 0x9c) = local_4a8;
      *(short *)(param_1 + 0xa0) = local_4a4._0_2_;
    }
    *(undefined2 *)(param_1 + 0xa4) = local_4a0._0_2_;
    *(undefined2 *)(param_1 + 0xa6) = local_4a0._2_2_;
    *(undefined2 *)(param_1 + 0xa8) = local_49c._0_2_;
    *(uint *)(param_1 + 0xac) = local_498;
    if (((uVar12 != (local_498 >> 7 & 1)) ||
        ((uVar12 != 0 &&
         ((sVar9 = FUN_1006d180(auStack_477,local_478,param_1 + 0x18d,
                                *(undefined1 *)(param_1 + 0x18c)), sVar9 != 0 ||
          (sVar9 = FUN_1006d180(auStack_237,local_238,param_1 + 0x20d,
                                *(undefined1 *)(param_1 + 0x20c)), sVar9 != 0)))))) ||
       ((uVar12 == 0 &&
        (sVar9 = FUN_1006d180(auStack_137,local_138,param_1 + 0x30d,*(undefined1 *)(param_1 + 0x30c)
                             ), sVar9 != 0)))) {
      FUN_10003940(param_1,0);
    }
    for (uVar12 = 0; uVar12 < 5; uVar12 = uVar12 + 1) {
      local_338 = FUN_10042f80(*(undefined4 *)(local_380[uVar12] + 0x2c),auStack_337,0xff);
      puVar13 = (undefined1 *)(param_1 + uVar12 * 0x144 + 0x57c);
      uVar11 = FUN_100537e0(*(undefined4 *)(local_36c[uVar12] + 0x34),0,puVar13 + 1,0x1f);
      *puVar13 = uVar11;
      uVar11 = FUN_1006d670(0x2a,auStack_337,local_338,param_1 + uVar12 * 0x144 + 0x45d,0xff);
      *(undefined1 *)(param_1 + uVar12 * 0x144 + 0x45c) = uVar11;
      if (*(char *)(param_1 + uVar12 * 0x144 + 0x45c) != '\0') {
        bVar1 = true;
      }
      iVar5 = FUN_1006ced0(0x3a,param_1 + uVar12 * 0x144 + 0x45d,
                           *(undefined1 *)(param_1 + uVar12 * 0x144 + 0x45c));
      *(ushort *)(param_1 + uVar12 * 0x144 + 0x45a) =
           ~((short)((ushort)((uint)-iVar5 >> 0x10) | (ushort)((uint)iVar5 >> 0x10)) >> 0xf) &
           0x157b;
    }
    if ((!bVar1) || (*(char *)(param_1 + 0xcc) == '\0')) {
      *(uint *)(param_1 + 0xac) = *(uint *)(param_1 + 0xac) & 0xfffffffe;
    }
    FUN_1006ea80(*(uint *)(param_1 + 0xac) >> 4 & 1);
    if ((*(uint *)(param_1 + 0xac) & 1) == 0) {
      FUN_1002a500(*(undefined4 *)(param_1 + 0x2c));
    }
    else {
      FUN_1002a410(*(undefined4 *)(param_1 + 0x2c),300000,1);
      FUN_1002a570(*(undefined4 *)(param_1 + 0x2c));
    }
    FUN_10008af0(param_1);
    FUN_10009d10(param_1,&local_4d8);
    FUN_10006590(param_1);
    sVar9 = FUN_1006d180(auStack_4c7,local_4c8,param_1 + 0x16d,*(undefined1 *)(param_1 + 0x16c));
    if (sVar9 != 0) {
      FUN_10028dc0(0x455,0,0,0,0,0,0);
    }
    if (bVar2) {
      FUN_10028dc0(0x453,0,0,0,0,0,0);
    }
    FUN_10004530(param_1);
    FUN_10055480(&local_4d8,0);
    local_3f8[0] = &PTR_PTR_1008f480;
    FUN_10036850(local_3f8,0);
    uVar3 = 1;
  }
  else {
    FUN_100578e0();
    uVar3 = 0;
  }
  return uVar3;
}

