
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

void FUN_10002dd0(uint param_1)

{
  undefined *puVar1;
  char cVar7;
  int iVar2;
  int iVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  byte bVar8;
  undefined4 uVar9;
  undefined1 auStack_140 [128];
  undefined1 auStack_64 [4];
  int local_60;
  undefined **local_5c [3];
  undefined4 local_50;
  int local_48;
  undefined1 *local_2c;
  
  if ((*(int *)(param_1 + 0x18) == 0) || (*(short *)(param_1 + 0xa2) == 0)) {
    FUN_100578e0();
  }
  else {
    cVar7 = FUN_1000edb0(param_1);
    puVar1 = PTR_DAT_10088d8c;
    if (cVar7 == '\0') {
      uVar9 = *(undefined4 *)(PTR_DAT_10088d8c + 0x20);
      _DAT_10096074 = _DAT_10096074 - *(int *)(PTR_DAT_10088d8c + 0xc);
      local_2c = auStack_140 + 0x80;
      iVar2 = FUN_10028fc0();
      if (iVar2 != 0) {
        iVar3 = FUN_10052c50(uVar9,1);
        uVar4 = FUN_10053290();
        FUN_1002c220(iVar2,1);
        FUN_1002c3b0(iVar2,0,uVar4,uVar9,0);
        local_60 = FUN_10078210(uVar4,uVar9,auStack_64);
        for (bVar8 = 0; bVar8 < 3; bVar8 = bVar8 + 1) {
          _DAT_10096074 =
               (_DAT_10096074 + *(int *)(puVar1 + (uint)bVar8 * 4)) -
               *(int *)(local_60 + (uint)bVar8 * 4);
        }
        _DAT_10096074 = _DAT_10096074 + *(int *)(local_60 + 0xc);
        if (local_60 != 0) {
          FUN_10052c10(local_60);
        }
        FUN_1002c2c0(iVar2);
        FUN_10053310(iVar3);
        if (iVar3 != 0) {
          FUN_10052e90(iVar3);
        }
        if (iVar2 != 0) {
          FUN_1002b2f0(iVar2);
        }
      }
      if (((_DAT_10096074 & 3) != 0) || (_DAT_10096074 >> 0x10 != param_1 >> 0x10)) {
        FUN_10027c30(1,1);
      }
      FUN_100208c0(local_5c);
      FUN_1003a510(local_50,1);
      do {
        while( true ) {
          FUN_100370f0(local_5c);
          iVar2 = FUN_100375d0(local_5c);
          if (iVar2 != 1) break;
          uVar9 = FUN_100430a0(*(undefined4 *)(local_48 + 0x2c));
          iVar2 = FUN_10052f80();
          if (iVar2 != 0) {
            uVar4 = FUN_10053290(uVar9);
            uVar5 = FUN_10056380(0,0);
            uVar6 = FUN_10052f80(uVar9);
            FUN_100568b0(uVar5,0x65,uVar4,uVar6);
            FUN_10005510(param_1,0x68,uVar5);
            FUN_100563d0(uVar5);
            FUN_10053310(uVar9);
            goto LAB_100030cc;
          }
          FUN_100578e0();
        }
      } while (iVar2 != 2);
LAB_100030cc:
      local_5c[0] = &PTR_PTR_1008f398;
      FUN_10036850(local_5c,0);
    }
    else {
      FUN_100578e0();
    }
  }
  return;
}

